// SPDX-License-Identifier: GPL-2.0-only

/* WARNING: This implementation is not necessarily the same
 * as the tcp_cubic.c.  The purpose is mainly for testing
 * the kernel BPF logic.
 *
 * Highlights:
 * 1. CONFIG_HZ .kconfig map is used.
 * 2. In bictcp_update(), calculation is changed to use usec
 *    resolution (i.e. USEC_PER_JIFFY) instead of using jiffies.
 *    Thus, usecs_to_jiffies() is not used in the bpf_cubic.c.
 * 3. In bitctcp_update() [under tcp_friendliness], the original
 *    "while (ca->ack_cnt > delta)" loop is changed to the equivalent
 *    "ca->ack_cnt / delta" operation.
 *
 * # COMPILAÇÃO: 
 * sudo clang-14 -target bpf -D__TARGET_ARCH_x86 -g -O2 -Wall -c bpf_cubic.c -o bpf_cubic.o
 *
 * # Register eBPF program
 * $ sudo bpftool struct_ops register bpf_cubic.o
 * Registered tcp_congestion_ops cubic id <n>
 * 
 * # Set TCP congestion control algorithm to bpf_cubic
 * $ sudo sysctl -w net.ipv4.tcp_congestion_control=bpf_cubic
 * net.ipv4.tcp_congestion_control = bpf_cubic
 *
 * Unregister CCA
 * $ sudo bpftool struct_ops unregister name cubic
 * Unregistered tcp_congestion_ops cubic id 101
 *
 * Desliga a interface gráfica
 * sudo systemctl stop gdm
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
static bool before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)

extern __u32 tcp_slow_start(struct tcp_sock *tp, __u32 acked) __ksym;
extern void tcp_cong_avoid_ai(struct tcp_sock *tp, __u32 w, __u32 acked) __ksym;

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

#define CUBIC_BETA_DEFAULT 717
#define CUBIC_BIC_SCALE_DEFAULT 41
#define CUBIC_BIC_SCALE_MIN     10
#define CUBIC_BIC_SCALE_MAX     60
#define CUBIC_MULT_RTT 5


static int fast_convergence = 1;
// static const int beta = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh;
// static const int bic_scale = 41;
static int tcp_friendliness = 1;

static int hystart = 1;
static int hystart_detect = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window = 16;
static int hystart_ack_delta_us = 2000;

// static const __u32 cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */
// static const __u32 beta_scale = 8*(BICTCP_BETA_SCALE+cubic_beta()) / 3
// 				/ (BICTCP_BETA_SCALE - cubic_beta());

/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
 * the unit of K is bictcp_HZ=2^10, not HZ
 *
 *  c = bic_scale >> 10
 *  rtt = 100ms
 *
 * the following code has been designed and tested for
 * cwnd < 1 million packets
 * RTT < 100 seconds
 * HZ < 1,000,00  (corresponding to 10 nano-second)
 */

/* 1/c * 2^2*bictcp_HZ * srtt, 2^40 */

/* Redefinição do parâmetro beta, anteriormente constante, agora mutável via map eBPF*/
/* Definição do struct e map eBPF*/

/*#######################################################################
  #######################################################################*/
  #ifndef HYSTART_MIN_SAMPLES
  #define HYSTART_MIN_SAMPLES 8
  #endif
  
/* Estrutura para retornar os valores calculados */
struct rtt_metrics {
    __u32 min_rtt;          /* RTT mínimo histórico */
    __u32 current_min;      /* Menor RTT atual da rodada */
    __u32 absolute_variation; /* Variação absoluta (current - min) */
    __u32 relative_variation; /* Variação relativa em porcentagem */
    __u8  is_elevated;      /* 1 se RTT > min + 25%, 0 caso contrário */
};

/* Função que APENAS calcula métricas, NÃO modifica a estrutura original */
static struct rtt_metrics calculate_rtt_metrics(const struct bictcp *ca, __u32 current_delay)
{
    struct rtt_metrics metrics = {0};
    
    /* 1. Obter RTT mínimo histórico da estrutura (apenas leitura) */
    metrics.min_rtt = ca->delay_min;
    
    /* 2. Calcular menor RTT considerando histórico e atual */
    metrics.current_min = ca->curr_rtt;
    if (current_delay < metrics.current_min || ca->sample_cnt == 0) {
        metrics.current_min = current_delay;
    }
    
    /* 3. Calcular variação absoluta (se temos dados suficientes) */
    if (ca->sample_cnt >= HYSTART_MIN_SAMPLES - 1) { /* -1 pois current_delay é nova amostra */
        if (metrics.current_min > metrics.min_rtt && metrics.min_rtt > 0) {
            metrics.absolute_variation = metrics.current_min - metrics.min_rtt;
            
            /* 4. Calcular variação relativa em porcentagem */
            metrics.relative_variation = (metrics.absolute_variation * 100) / metrics.min_rtt;
            
            /* 5. Verificar se RTT está elevado (>25% do mínimo) */
            __u32 threshold = metrics.min_rtt + (metrics.min_rtt >> 2); /* +25% */
            metrics.is_elevated = (metrics.current_min > threshold) ? 1 : 0;
        }
    }
    
    return metrics;
}

/* Versão alternativa que retorna apenas os valores essenciais via ponteiros */
static void get_rtt_stats(const struct sock *sk, __u32 current_delay,
                         __u32 *min_rtt, __u32 *variation, __u8 *status)
{
    const struct bictcp *ca = inet_csk_ca(sk);
    
    /* RTT mínimo histórico */
    if (min_rtt) {
        *min_rtt = ca->delay_min;
    }
    
    /* Calcular variação se temos dados suficientes */
    if (variation || status) {
        __u32 current_min = ca->curr_rtt;
        if (current_delay < current_min || ca->sample_cnt == 0) {
            current_min = current_delay;
        }
        
        if (ca->sample_cnt >= HYSTART_MIN_SAMPLES - 1 && 
            current_min > ca->delay_min && ca->delay_min > 0) {
            
            __u32 abs_variation = current_min - ca->delay_min;
            
            /* Variação absoluta */
            if (variation) {
                *variation = abs_variation;
            }
            
            /* Status (elevado ou normal) */
            if (status) {
                __u32 threshold = ca->delay_min + (ca->delay_min >> 2); /* +25% */
                *status = (current_min > threshold) ? 1 : 0;
            }
        } else {
            if (variation) *variation = 0;
            if (status) *status = 0;
        }
    }
}

/* Função mais simples: apenas retorna o RTT mínimo e variação atual */
static __u32 get_current_rtt_variation(const struct sock *sk, __u32 current_delay)
{
    const struct bictcp *ca = inet_csk_ca(sk);
    
    /* Verificar se temos amostras suficientes */
    if (ca->sample_cnt < HYSTART_MIN_SAMPLES - 1 || ca->delay_min == 0) {
        return 0;
    }
    
    /* Calcular mínimo atual (considerando nova amostra) */
    __u32 current_min = ca->curr_rtt;
    if (current_delay < current_min) {
        current_min = current_delay;
    }
    
    /* Calcular e retornar variação */
    if (current_min > ca->delay_min) {
        return current_min - ca->delay_min;
    }
    
    return 0;
}

/* Função que apenas lê e retorna o RTT mínimo histórico */
static __u32 get_historical_min_rtt(const struct sock *sk)
{
    const struct bictcp *ca = inet_csk_ca(sk);
    return ca->delay_min;
}
/*  #######################################################################
  #######################################################################
*/
struct cubic_config {
	__u32 beta;   /* scaled by BICTCP_BETA_SCALE */
	__u32 bic_scale;  /* cubic scale (default 41) */
	__u32 mult_rtt;  /* multiplicador rtt (default 5) */
	};
				

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cubic_config);
	} cubic_cfg SEC(".maps");
				
/* Fim das definições do struct e map eBPF*/
static __always_inline __u32 cubic_bic_scale(void)
{
	struct cubic_config *cfg;
	__u32 key = 0;
	__u32 s;

	cfg = bpf_map_lookup_elem(&cubic_cfg, &key);
	if (!cfg || cfg->bic_scale == 0)
		return CUBIC_BIC_SCALE_DEFAULT;

	s = cfg->bic_scale;

	if (s < CUBIC_BIC_SCALE_MIN)
		s = CUBIC_BIC_SCALE_MIN;
	if (s > CUBIC_BIC_SCALE_MAX)
		s = CUBIC_BIC_SCALE_MAX;

	return s;
}


/* BIC TCP Parameters */
struct bpf_bictcp {
	__u32	cnt;		/* increase cwnd by 1 after ACKs */
	__u32	last_max_cwnd;	/* last maximum snd_cwnd */
	__u32	last_cwnd;	/* the last snd_cwnd */
	__u32	last_time;	/* time when updated last_cwnd */
	__u32	bic_origin_point;/* origin point of bic function */
	__u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	__u32	delay_min;	/* min delay (usec) */
	__u32	epoch_start;	/* beginning of an epoch */
	__u32	ack_cnt;	/* number of acks */
	__u32	tcp_cwnd;	/* estimated tcp cwnd */
	__u16	unused;
	__u8	sample_cnt;	/* number of samples to decide curr_rtt */
	__u8	found;		/* the exit point is found? */
	__u32	round_start;	/* beginning of each round */
	__u32	end_seq;	/* end_seq of the round */
	__u32	last_ack;	/* last time when the ACK spacing is close */
	__u32	curr_rtt;	/* the minimum rtt of current round */
};

static void bictcp_reset(struct bpf_bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

extern unsigned long CONFIG_HZ __kconfig;
#define HZ CONFIG_HZ
#define USEC_PER_MSEC	1000UL
#define USEC_PER_SEC	1000000UL
#define USEC_PER_JIFFY	(USEC_PER_SEC / HZ)

static __always_inline __u32 cubic_beta_scale(__u32 beta)
{
	if (beta >= BICTCP_BETA_SCALE)
		beta = BICTCP_BETA_SCALE - 1;

	return (8 * (BICTCP_BETA_SCALE + beta)) /
	       (3 * (BICTCP_BETA_SCALE - beta));
}



static __always_inline __u32 cubic_beta(void)
{
	struct cubic_config *cfg;
	__u32 key = 0;

	cfg = bpf_map_lookup_elem(&cubic_cfg, &key);
	if (!cfg || cfg->beta == 0)
		return CUBIC_BETA_DEFAULT;

	return cfg->beta;
}


static __always_inline __u32 cubic_mult_rtt(void)
{
	struct cubic_config *cfg;
	__u32 key = 0;

	cfg = bpf_map_lookup_elem(&cubic_cfg, &key);
	if (!cfg || cfg->mult_rtt == 0)
		return CUBIC_MULT_RTT;

	return cfg->mult_rtt;
}

static __u64 div64_u64(__u64 dividend, __u64 divisor)
{
	return dividend / divisor;
}

#define div64_ul div64_u64

#define BITS_PER_U64 (sizeof(__u64) * 8)
static int fls64(__u64 x)
{
	int num = BITS_PER_U64 - 1;

	if (x == 0)
		return 0;

	if (!(x & (~0ull << (BITS_PER_U64-32)))) {
		num -= 32;
		x <<= 32;
	}
	if (!(x & (~0ull << (BITS_PER_U64-16)))) {
		num -= 16;
		x <<= 16;
	}
	if (!(x & (~0ull << (BITS_PER_U64-8)))) {
		num -= 8;
		x <<= 8;
	}
	if (!(x & (~0ull << (BITS_PER_U64-4)))) {
		num -= 4;
		x <<= 4;
	}
	if (!(x & (~0ull << (BITS_PER_U64-2)))) {
		num -= 2;
		x <<= 2;
	}
	if (!(x & (~0ull << (BITS_PER_U64-1))))
		num -= 1;

	return num + 1;
}

static __u32 bictcp_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

static void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bpf_bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock_us(sk);
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = ~0U;
	ca->sample_cnt = 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_cubic_init, struct sock *sk)
{
	struct bpf_bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);

	if (hystart)
		bictcp_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

SEC("struct_ops")
void BPF_PROG(bpf_cubic_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bpf_bictcp *ca = inet_csk_ca(sk);
		__u32 now = tcp_jiffies32;
		__s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

/*
 * cbrt(x) MSB values for x MSB values in [0..63].
 * Precomputed then refined by hand - Willy Tarreau
 *
 * For x in [0..63],
 *   v = cbrt(x << 18) - 1
 *   cbrt(x) = (v[x] + 10) >> 6
 */
static const __u8 v[] = {
	/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
	/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
	/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
	/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
	/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
	/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
	/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
	/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
};

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static __u32 cubic_root(__u64 a)
{
	__u32 x, b, shift;

	if (a < 64) {
		/* a in [0..63] */
		return ((__u32)v[(__u32)a] + 35) >> 6;
	}

	b = fls64(a);
	b = ((b * 84) >> 8) - 1;
	shift = ((__u32)a >> (b * 3));

	/* it is needed for verifier's bound check on v */
	if (shift >= 64)
		return 0;

	x = ((__u32)(((__u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (__u32)div64_u64(a, (__u64)x * (__u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
 static void bictcp_update(struct bpf_bictcp *ca, __u32 cwnd, __u32 acked)
{
	__u32 bic_scale = cubic_bic_scale();
	__u32 cube_rtt_scale = bic_scale * 10;
	__u64 cube_factor =
		(1ull << (10 + 3 * BICTCP_HZ)) / (bic_scale * 10);

	__u32 delta, bic_target, max_cnt;
	__u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (__s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those variables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (__s32)(tcp_jiffies32 - ca->epoch_start) * USEC_PER_JIFFY;
	t += ca->delay_min;
	/* change the unit from usec to bictcp_HZ */
	t <<= BICTCP_HZ;
	t /= USEC_PER_SEC;

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		// __u32 scale = beta_scale;
		__u32 beta = cubic_beta();
		__u32 scale = cubic_beta_scale(beta);

		__u32 n;

		/* update tcp cwnd */
		delta = (cwnd * scale) >> 3;
		if (ca->ack_cnt > delta && delta) {
			n = ca->ack_cnt / delta;
			ca->ack_cnt -= n * delta;
			ca->tcp_cwnd += n;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

SEC("struct_ops")
void BPF_PROG(bpf_cubic_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bpf_bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		if (hystart && after(ack, ca->end_seq))
			bictcp_hystart_reset(sk);
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	bictcp_update(ca, tp->snd_cwnd, acked);
	tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_cubic_recalc_ssthresh, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bpf_bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + cubic_beta()))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	return max((tp->snd_cwnd * cubic_beta()) / BICTCP_BETA_SCALE, 2U);

}

// SEC("struct_ops")
// void BPF_PROG(bpf_cubic_state, struct sock *sk, __u8 new_state)
// {
// 	struct bpf_bictcp *ca = inet_csk_ca(sk);
// 	__u32 current_delay = ca->curr_rtt;
// 	struct rtt_metrics stats = calculate_rtt_metrics(ca, ca->curr_rtt);

// 	if (new_state == TCP_CA_Loss) {
// 		bictcp_reset(inet_csk_ca(sk));
// 		bictcp_hystart_reset(sk);
// 	}
// }

SEC("struct_ops")
void BPF_PROG(bpf_cubic_state, struct sock *sk, __u8 new_state)
{
	struct bpf_bictcp *ca = inet_csk_ca(sk);
	
	if (!ca) return;
	
	/* Condição 1: Estado é Loss? */
	__u8 is_loss_state = (new_state == TCP_CA_Loss);
	
	/* Condição 2: RTT aumentou 5x? */
	__u8 is_rtt_x = 0; 
	int m = (int)(cubic_mult_rtt());
	if (ca->delay_min > 0 && ca->curr_rtt > 0) {
		/* Calcula se curr_rtt é pelo menos 5x delay_min */
		is_rtt_x = (ca->curr_rtt >= ca->delay_min * m); /*Este valor de 5x poderia ser um map eBPF*/
	}
	
	/* APENAS se AMBAS condições forem verdadeiras */
	if (is_loss_state && is_rtt_x) {
		bictcp_reset(ca);
		bictcp_hystart_reset(sk);
		
		// bpf_printk("Reset executado: Loss AND RTT 5x aumento\n");
	}
	/* else: não faz nada em caso de Loss sem aumento de RTT */
}

// SEC("struct_ops")
// void BPF_PROG(bpf_cubic_state, struct sock *sk, __u8 new_state)
// {
// 	struct bpf_bictcp *ca = inet_csk_ca(sk);
	
// 	/* 1. CALCULAR MÉTRICAS DE RTT (se desejado) */
// 	/* Pega o current_delay atual da estrutura */
// 	__u32 current_delay = ca->curr_rtt;
	
// 	/* Calcula as métricas (OPCIONAL - apenas para monitoramento) */
// 	struct rtt_metrics stats = calculate_rtt_metrics(ca, current_delay);
	
// 	/* 3. LÓGICA DE MUDANÇA DE ESTADO (obrigatória) */
// 	if (new_state == TCP_CA_Loss) {
// 		/* Reset do Cubic ao detectar perda */
// 		bictcp_reset(ca);
// 		bictcp_hystart_reset(sk);
// }

#define GSO_MAX_SIZE		65536

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static __u32 hystart_ack_delay(struct sock *sk)
{
	unsigned long rate;

	rate = sk->sk_pacing_rate;
	if (!rate)
		return 0;
	return min((__u64)USEC_PER_MSEC,
		   div64_ul((__u64)GSO_MAX_SIZE * 4 * USEC_PER_SEC, rate));
}

static void hystart_update(struct sock *sk, __u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bpf_bictcp *ca = inet_csk_ca(sk);
	__u32 threshold;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		__u32 now = bictcp_clock_us(sk);

		/* first detection parameter - ack-train detection */
		if ((__s32)(now - ca->last_ack) <= hystart_ack_delta_us) {
			ca->last_ack = now;

			threshold = ca->delay_min + hystart_ack_delay(sk);

			/* Hystart ack train triggers if we get ack past
			 * ca->delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start.
			 */
			if (sk->sk_pacing_status == SK_PACING_NONE)
				threshold >>= 1;

			if ((__s32)(now - ca->round_start) > threshold) {
				ca->found = 1;
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->curr_rtt > delay)
			ca->curr_rtt = delay;
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found = 1;
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}
}

int bpf_cubic_acked_called = 0;

SEC("struct_ops")
void BPF_PROG(bpf_cubic_acked, struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bpf_bictcp *ca = inet_csk_ca(sk);
	__u32 delay;

	bpf_cubic_acked_called = 1;
	/* Some calls are for duplicates without timestamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (__s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (!ca->found && tcp_in_slow_start(tp) && hystart &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

extern __u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;

SEC("struct_ops")
__u32 BPF_PROG(bpf_cubic_undo_cwnd, struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}

SEC(".struct_ops")
struct tcp_congestion_ops cubic = {
	.init		= (void *)bpf_cubic_init,
	.ssthresh	= (void *)bpf_cubic_recalc_ssthresh,
	.cong_avoid	= (void *)bpf_cubic_cong_avoid,
	.set_state	= (void *)bpf_cubic_state,
	.undo_cwnd	= (void *)bpf_cubic_undo_cwnd,
	.cwnd_event	= (void *)bpf_cubic_cwnd_event,
	.pkts_acked     = (void *)bpf_cubic_acked,
	.name		= "bpf_cubic",
};
