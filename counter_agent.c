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

// elenco di contatori => todo fare una struct
static u_int64_t tcp_counter;
static u_int64_t tcp_syn_counter;
static u_int64_t udp_packets_counter;
static u_int64_t udp_packets_counter_53;
static u_int64_t udp_throughtput_counter;
static u_int64_t udp_throughtput_counter_53;

// vettore per la gestione dei server da proteggere
// todo: usare network order o host order?
typedef struct
{
	__be16 port;
	__be32 ip;
	uint64_t counter;
	uint64_t syn_counter;

} server_ip_port;
// todo: allocare dinamicamente in base all'input
unsigned servers_size = 0;
server_ip_port *servers;

// todo: togliere parametri
module_param(co_dev_name, charp, 0000);
MODULE_PARM_DESC(co_dev_name, "Name of the interface connected to the CO");

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
	int i;
	char buf[PROCFS_MAX_SIZE];
	int len = 0;
	unsigned char bytes[4];
	if (*ppos > 0 || count < PROCFS_MAX_SIZE)
		return 0;
	len += sprintf(buf + len, "tcp_packets %llu\n", tcp_counter);
	len += sprintf(buf + len, "tcp_syn_packets %llu\n", tcp_syn_counter);
	len += sprintf(buf + len, "udp_packets %llu\n", udp_packets_counter);
	len += sprintf(buf + len, "udp_throughtput %llu,\n", udp_throughtput_counter);
	len += sprintf(buf + len, "udp_packets_53 %llu\n", udp_packets_counter_53);
	len += sprintf(buf + len, "udp_throughtput_53 %llu\n", udp_throughtput_counter_53);
	for (i = 0; i < servers_size; i++)
	{
		bytes[0] = servers[i].ip & 0xFF;
		bytes[1] = (servers[i].ip >> 8) & 0xFF;
		bytes[2] = (servers[i].ip >> 16) & 0xFF;
		bytes[3] = (servers[i].ip >> 24) & 0xFF;
		len += sprintf(buf + len, "tcp_packets_%d.%d.%d.%d:%d %llu\n",
					   bytes[0], bytes[1], bytes[2], bytes[3], ntohs(servers[i].port), servers[i].counter);
		len += sprintf(buf + len, "tcp_syn_packets_%d.%d.%d.%d:%d %llu\n",
					   bytes[0], bytes[1], bytes[2], bytes[3], ntohs(servers[i].port), servers[i].syn_counter);
	}

	if (copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static ssize_t procfile_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	int c, num;
	int servers_counter = 0;
	int i = 0;
	unsigned char bytes[4];
	char buf[PROCFS_MAX_SIZE];
	char delim[] = "\n";
	char *token, *cur;

	if (*ppos > 0 || count > PROCFS_MAX_SIZE)
		return -EFAULT;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	// se l'ultimo carattere è un \n lo cancello
	c = strlen(buf);
	// if (buf[c - 1] == '\n')
	// 	buf[c - 1] = '\0';

	// conto il numero di righe per allocare il vettore degli ip
	for (i = 0; i < c; i++)
		if (buf[i] == '\n')
			servers_counter++;

	// libero il vettore se è già allocato
	if (servers_size > 0)
		kfree(servers);

	// alloco il vettore
	servers = (server_ip_port *)kmalloc(sizeof(server_ip_port) * servers_counter, GFP_KERNEL);
	if (servers == NULL)
	{
		printk("Malloc error");
		servers_size = 0;
		// todo: il valore di ritorno ha senso?
		return -EFAULT;
	}
	servers_size = servers_counter;

	// conto il numero di righe per allocare il vettore degli ip
	i = 0;
	token = buf;
	cur = buf;
	printk("---- %d - %p", servers_size, buf);
	while ((token = strsep(&cur, delim)) != NULL)
	{
		num = sscanf(token, "%hhd.%hhd.%hhd.%hhd %hd",
					 &bytes[0], &bytes[1], &bytes[2], &bytes[3], &(servers[i].port));
		// printk("%s fine_riga___ %p\n", token, token);
		// printk("num %d", num);
		// todo: il valore di ritorno ha senso?
		if (num != 5)
			return c;
		servers[i].port = htons(servers[i].port);
		servers[i].ip = *(unsigned int *)bytes;
		servers[i].counter = 0;
		servers[i].syn_counter = 0;
		i++;
	}

	// token = buf;
	// cur = buf;
	// printk("---- %d - %p", servers_size, buf);
	// while ((token = strsep(&cur, delim)) != NULL)
	// {
	// 	printk("%s fine_riga___ %p\n", token, token);
	// }

	// // riempio il vettore con i dati del file
	// token = buf;
	// cur = buf;
	// printk("---- %d - %p", servers_size, buf);

	// while ((token = strsep(&cur, delim)) != NULL)
	// {
	// 	printk("%s fine_riga\n", token);
	// 	*bytes = *bytes;
	// 	i = 1;
	// 	num = 1;
		// num = sscanf(buf, "%hhd.%hhd.%hhd.%hhd %hd",
		// 			 &bytes[0], &bytes[1], &bytes[2], &bytes[3], &(servers[i].port));
		// printk("num %d", num);
		// if (num != 5)
		// 	return -EFAULT;
		// servers[i].port = htons(servers[i].port);
		// servers[i].ip = *(unsigned int *)bytes;
		// servers[i].counter = 0;
		// servers[i].syn_counter = 0;
		// i++;
	// }
	// printk(buf);
	// printk("%s %d", buf, c);
	*ppos = c;
	return c;
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

	// servers[0].port = htons(80);
	// servers[0].ip = htonl(3232235831); // 192.168.1.55
	// servers[1].port = htons(8096);
	// servers[1].ip = htonl(3232235831); // 192.168.1.55

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
	if (servers_size > 0)
		kfree(servers);
	printk(KERN_INFO "tcp/udp packet counter: cleanup_module() called\n");
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int i;
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
				}
				for (i = 0; i < servers_size; i++)
				{
					if (tcph->dest == servers[i].port && iph->daddr == servers[i].ip)
					{
						servers[i].counter++;
						if (tcph->syn)
						{
							servers[i].syn_counter++;
						}
						break;
					}
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

				// verifico che la porta sorgente sia la 53 (DNS)
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
