/*
 * HD-audio controller (Azalia) registers and helpers
 *
 * For traditional reasons, we still use azx_ prefix here
 */

#ifndef __SOUND_HDA_REGISTER_H
#define __SOUND_HDA_REGISTER_H

#include <linux/io.h>
#include <sound/hdaudio.h>

#define AZX_REG_GCAP			0x00
#define   AZX_GCAP_64OK		(1 << 0)   /* 64bit address support */
#define   AZX_GCAP_NSDO		(3 << 1)   /* # of serial data out signals */
#define   AZX_GCAP_BSS		(31 << 3)  /* # of bidirectional streams */
#define   AZX_GCAP_ISS		(15 << 8)  /* # of input streams */
#define   AZX_GCAP_OSS		(15 << 12) /* # of output streams */
#define AZX_REG_VMIN			0x02
#define AZX_REG_VMAJ			0x03
#define AZX_REG_OUTPAY			0x04
#define AZX_REG_INPAY			0x06
#define AZX_REG_GCTL			0x08
#define   AZX_GCTL_RESET	(1 << 0)   /* controller reset */
#define   AZX_GCTL_FCNTRL	(1 << 1)   /* flush control */
#define   AZX_GCTL_UNSOL	(1 << 8)   /* accept unsol. response enable */
#define AZX_REG_WAKEEN			0x0c
#define AZX_REG_STATESTS		0x0e
#define AZX_REG_GSTS			0x10
#define   AZX_GSTS_FSTS		(1 << 1)   /* flush status */
#define AZX_REG_INTCTL			0x20
#define AZX_REG_INTSTS			0x24
#define AZX_REG_WALLCLK			0x30	/* 24Mhz source */
#define AZX_REG_OLD_SSYNC		0x34	/* SSYNC for old ICH */
#define AZX_REG_SSYNC			0x38
#define AZX_REG_CORBLBASE		0x40
#define AZX_REG_CORBUBASE		0x44
#define AZX_REG_CORBWP			0x48
#define AZX_REG_CORBRP			0x4a
#define   AZX_CORBRP_RST	(1 << 15)  /* read pointer reset */
#define AZX_REG_CORBCTL			0x4c
#define   AZX_CORBCTL_RUN	(1 << 1)   /* enable DMA */
#define   AZX_CORBCTL_CMEIE	(1 << 0)   /* enable memory error irq */
#define AZX_REG_CORBSTS			0x4d
#define   AZX_CORBSTS_CMEI	(1 << 0)   /* memory error indication */
#define AZX_REG_CORBSIZE		0x4e

#define AZX_REG_RIRBLBASE		0x50
#define AZX_REG_RIRBUBASE		0x54
#define AZX_REG_RIRBWP			0x58
#define   AZX_RIRBWP_RST	(1 << 15)  /* write pointer reset */
#define AZX_REG_RINTCNT			0x5a
#define AZX_REG_RIRBCTL			0x5c
#define   AZX_RBCTL_IRQ_EN	(1 << 0)   /* enable IRQ */
#define   AZX_RBCTL_DMA_EN	(1 << 1)   /* enable DMA */
#define   AZX_RBCTL_OVERRUN_EN	(1 << 2)   /* enable overrun irq */
#define AZX_REG_RIRBSTS			0x5d
#define   AZX_RBSTS_IRQ		(1 << 0)   /* response irq */
#define   AZX_RBSTS_OVERRUN	(1 << 2)   /* overrun irq */
#define AZX_REG_RIRBSIZE		0x5e

#define AZX_REG_IC			0x60
#define AZX_REG_IR			0x64
#define AZX_REG_IRS			0x68
#define   AZX_IRS_VALID		(1<<1)
#define   AZX_IRS_BUSY		(1<<0)

#define AZX_REG_DPLBASE			0x70
#define AZX_REG_DPUBASE			0x74
#define   AZX_DPLBASE_ENABLE	0x1	/* Enable position buffer */

/* SD offset: SDI0=0x80, SDI1=0xa0, ... SDO3=0x160 */
enum { SDI0, SDI1, SDI2, SDI3, SDO0, SDO1, SDO2, SDO3 };

/* stream register offsets from stream base */
#define AZX_REG_SD_CTL			0x00
#define AZX_REG_SD_STS			0x03
#define AZX_REG_SD_LPIB			0x04
#define AZX_REG_SD_CBL			0x08
#define AZX_REG_SD_LVI			0x0c
#define AZX_REG_SD_FIFOW		0x0e
#define AZX_REG_SD_FIFOSIZE		0x10
#define AZX_REG_SD_FORMAT		0x12
#define AZX_REG_SD_BDLPL		0x18
#define AZX_REG_SD_BDLPU		0x1c

/* Haswell/Broadwell display HD-A controller Extended Mode registers */
#define AZX_REG_HSW_EM4			0x100c
#define AZX_REG_HSW_EM5			0x1010

/* PCI space */
#define AZX_PCIREG_TCSEL		0x44

/*
 * other constants
 */

/* max number of fragments - we may use more if allocating more pages for BDL */
#define BDL_SIZE		4096
#define AZX_MAX_BDL_ENTRIES	(BDL_SIZE / 16)
#define AZX_MAX_FRAG		32
/* max buffer size - no h/w limit, you can increase as you like */
#define AZX_MAX_BUF_SIZE	(1024*1024*1024)

/* RIRB int mask: overrun[2], response[0] */
#define RIRB_INT_RESPONSE	0x01
#define RIRB_INT_OVERRUN	0x04
#define RIRB_INT_MASK		0x05

/* STATESTS int mask: S3,SD2,SD1,SD0 */
#define STATESTS_INT_MASK	((1 << HDA_MAX_CODECS) - 1)

/* SD_CTL bits */
#define SD_CTL_STREAM_RESET	0x01	/* stream reset bit */
#define SD_CTL_DMA_START	0x02	/* stream DMA start bit */
#define SD_CTL_STRIPE		(3 << 16)	/* stripe control */
#define SD_CTL_TRAFFIC_PRIO	(1 << 18)	/* traffic priority */
#define SD_CTL_DIR		(1 << 19)	/* bi-directional stream */
#define SD_CTL_STREAM_TAG_MASK	(0xf << 20)
#define SD_CTL_STREAM_TAG_SHIFT	20

/* SD_CTL and SD_STS */
#define SD_INT_DESC_ERR		0x10	/* descriptor error interrupt */
#define SD_INT_FIFO_ERR		0x08	/* FIFO error interrupt */
#define SD_INT_COMPLETE		0x04	/* completion interrupt */
#define SD_INT_MASK		(SD_INT_DESC_ERR|SD_INT_FIFO_ERR|\
				 SD_INT_COMPLETE)

/* SD_STS */
#define SD_STS_FIFO_READY	0x20	/* FIFO ready */

/* INTCTL and INTSTS */
#define AZX_INT_ALL_STREAM	0xff	   /* all stream interrupts */
#define AZX_INT_CTRL_EN	0x40000000 /* controller interrupt enable bit */
#define AZX_INT_GLOBAL_EN	0x80000000 /* global interrupt enable bit */

/* below are so far hardcoded - should read registers in future */
#define AZX_MAX_CORB_ENTRIES	256
#define AZX_MAX_RIRB_ENTRIES	256

/*
 * helpers to read the stream position
 */
static inline unsigned int
snd_hdac_stream_get_pos_lpib(struct hdac_stream *stream)
{
	return snd_hdac_stream_readl(stream, SD_LPIB);
}

static inline unsigned int
snd_hdac_stream_get_pos_posbuf(struct hdac_stream *stream)
{
	return le32_to_cpu(*stream->posbuf);
}

#endif /* __SOUND_HDA_REGISTER_H */