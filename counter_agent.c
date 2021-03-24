#include <linux/module.h>
#include <linux/init.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>

#define PROCFS_NAME "udp_tcp_counter"
#define PROCFS_MAX_SIZE 1024

char procfs_buffer[PROCFS_MAX_SIZE];
struct proc_dir_entry *proc_file;

static struct nf_hook_ops nfho;

// elenco di contatori =>
// e uso il fast path posso solo contare il primo pacchetto del flusso
// quindi conto i syn, in futuro lo espanderò con altre metriche
typedef struct
{
	u_int64_t tcp_syn_counter;
} packets_counter;
static packets_counter counter;


static ssize_t procfile_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos);
static ssize_t procfile_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct file_operations myops =
	{
		.owner = THIS_MODULE,
		.read = procfile_read,
		.write = procfile_write,
};

static ssize_t procfile_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	char buf[PROCFS_MAX_SIZE];
	int len = 0;
	if (*ppos > 0 || count < PROCFS_MAX_SIZE)
		return 0;
	len += sprintf(buf + len, "{\n");
	len += sprintf(buf + len, "  \"tcp_syn_packets\": %llu,\n", counter.tcp_syn_counter);
	len -= 2;
	len += sprintf(buf + len, "\n}\n");
	if (copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static ssize_t procfile_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	int c;
	char buf[PROCFS_MAX_SIZE];

	if (*ppos > 0 || count > PROCFS_MAX_SIZE){
		printk("Count > PROCFS_MAX_SIZE o pps > 0");
		return -EFAULT;
	}
	if (copy_from_user(buf, ubuf, count)){
		printk("Copy buffer error");
		return -EFAULT;

	}

	c = strlen(buf);

	*ppos = c;
	return c;
}

int __init init_module(void)
{
	int result;
	struct net_device *dev;

	counter.tcp_syn_counter = 0;

	proc_file = proc_create(PROCFS_NAME, 0644, NULL, &myops);
	if (proc_file == NULL)
	{
		proc_remove(proc_file);
		printk(KERN_ALERT "Error: couldn't create proc file");
		return -ENOMEM;
	}

	// imposto l'hook per ascoltare il traffico in uscita
	// sull'interfaccia interface-vdsl0_835 (quella verso la wan)
	// eth0 per i test sul tgr
    dev = dev_get_by_name(&init_net, "eth0");

    if(!dev)
    {
	printk(KERN_ERR "tcp/udp packet counter: error net device missing!\n");
        return -1;
    }

	nfho.dev = dev;
	nfho.hook = (nf_hookfn *)hook_func; //function to call when conditions are met
	nfho.hooknum = NF_INET_POST_ROUTING;
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
	printk(KERN_INFO "tcp/udp packet counter: cleanup_module() called\n");
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
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
				if (tcph->syn)
				{
					counter.tcp_syn_counter++;
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
