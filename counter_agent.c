#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/route.h>
#include <net/flow.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/list.h>

#define PROCFS_NAME "udp_tcp_counter"
#define PROCFS_MAX_SIZE 1024

char procfs_buffer[PROCFS_MAX_SIZE];
struct proc_dir_entry *proc_file;

// int co_ifindex;
static struct nf_hook_ops nfho;
static char *co_dev_name = "eth0";
static u_int64_t tcp_counter;
static u_int64_t tcp_syn_counter;
static u_int64_t udp_packets_counter;
static u_int64_t udp_packets_counter_53;
static u_int64_t udp_throughtput_counter;
static u_int64_t udp_throughtput_counter_53;

// todo: togliere parametri
module_param(co_dev_name, charp, 0000);
MODULE_PARM_DESC(co_dev_name, "Name of the interface connected to the CO");

static ssize_t procfile_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos);
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct file_operations myops =
	{
		.owner = THIS_MODULE,
		.read = procfile_read,
};

static ssize_t procfile_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	char buf[PROCFS_MAX_SIZE];
	int len = 0;
	if (*ppos > 0 || count < PROCFS_MAX_SIZE)
		return 0;
	len += sprintf(buf, "tcp_packets = %llu\n", tcp_counter);
	len += sprintf(buf + len, "tcp_syn_packets = %llu\n", tcp_syn_counter);
	len += sprintf(buf + len, "udp_packets = %llu\n", udp_packets_counter);
	len += sprintf(buf + len, "udp_throughtput = %llu\n", udp_throughtput_counter);
	len += sprintf(buf + len, "udp_packets_53 = %llu\n", udp_packets_counter_53);
	len += sprintf(buf + len, "udp_throughtput_53 = %llu\n", udp_throughtput_counter_53);

	if (copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

int __init init_module(void)
{
	int result;
	tcp_counter = 0;
	tcp_syn_counter = 0;
	udp_packets_counter = 0;
	udp_packets_counter_53 = 0;
	udp_throughtput_counter = 0;
	udp_throughtput_counter_53 = 0;

	proc_file = proc_create(PROCFS_NAME, 0644, NULL, &myops);
	if (proc_file == NULL)
	{
		proc_remove(proc_file);
		printk(KERN_ALERT "Error: couldn't create proc file");
		return -ENOMEM;
	}

	nfho.hook = (nf_hookfn *)hook_func; //function to call when conditions are met

	nfho.hooknum = NF_INET_PRE_ROUTING;

	nfho.pf = PF_INET; //IPV4 packets
	nfho.priority = NF_IP_PRI_FILTER;

	result = nf_register_net_hook(&init_net, &nfho);

	if (result)
	{
		printk(KERN_ERR "tcp/udp packet counter loaded: error nf_register_hook !\n");
		return -1;
	}

	printk(KERN_INFO "tcp/udp packet counter loaded.\n");

	return 0;
}

void __exit cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	proc_remove(proc_file);
	printk(KERN_INFO "IFACE_TRACK: cleanup_module() called\n");
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	if (skb)
	{
		// todo: non so bene cosa faccia
		if (skb_linearize(skb) == 0)
		{
			iph = ip_hdr(skb);
			if (!iph)
				return NF_ACCEPT;
			// controllo che il protocollo sopra ip sia tcp
			if (iph->protocol == IPPROTO_TCP)
			{
				tcph = tcp_hdr(skb);
				if (!tcph)
					return NF_ACCEPT;
				tcp_counter++;

				if (tcph->syn)
				{
					tcp_syn_counter++;
					// printk("Syn counter %llu \n", syn_counter);
				}
			}
			// controllo che il protocollo sopra ip sia udp
			if (iph->protocol == IPPROTO_UDP)
			{
				udph = udp_hdr(skb);
				if (!udph)
					return NF_ACCEPT;
				// incremento i contatori generici
				udp_packets_counter++;
				udp_throughtput_counter += skb->len;

				if (ntohs(udph->source) == 53)
				{
					udp_packets_counter_53++;
					udp_throughtput_counter_53 += skb->len;
				}
			}
		}
		else
			printk(KERN_ERR "skb error: linearize error");
	}
	else
		printk(KERN_ERR "skb error: skb is zero");

	return NF_ACCEPT;
}

MODULE_LICENSE("GPL");
