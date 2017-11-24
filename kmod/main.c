#include <linux/module.h>
#include <net/netlink.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>


#define NETLINK_TEST 17

static struct task_struct *t1;

struct config
{
	unsigned char	sPort[2];
	unsigned char	dPort[2];
	unsigned char	sIP[4];
	unsigned char	dIP[4];
	unsigned char	sMac[6];
	unsigned char	dMac[6];
};

struct configList
{
	unsigned char	type;
	unsigned char	report;
	struct config	packetConfig;
	struct	list_head	list;
};
struct configList listhead =
{
	.list=LIST_HEAD_INIT(listhead.list)
};

int PID = 0;

/* The netlink socket. */
static struct sock *test_nl_sock;
static struct nf_hook_ops nfhk_local_in;

static void printkHex(char *data, int data_len, int padding_len, char* pt_mark)
{	
	int i = 0;
	printk("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len+padding_len); i ++) 
	{
		if(0 == (i%16) && i != 0)
			printk("[%d]\n",i/16);
		printk("%02x ", data[i] & 0xFF);
	}
	printk("\n");
}

static int send_msg_to_user(int pid, void* str, int str_len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int len = str_len + 1;

	skb = nlmsg_new(len, GFP_KERNEL);
	if (!skb) {
		printk(KERN_ERR "nlmsg_new: couldn't alloc a sk_buff\n");
		return -ENOMEM;
	}

	nlh = nlmsg_put(skb, 0, 7438, 0, len, 0);
	if (!nlh) {
		printk(KERN_ERR "nlmsg_put: couldn't put nlmsghdr\n");
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	memcpy(NLMSG_DATA(nlh), str, len);
	printkHex(NLMSG_DATA(nlh), len, 0, "send_msg_to_user");

	return nlmsg_unicast(test_nl_sock, skb, pid);
}



static int netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	printk(KERN_INFO "receive from userspace: %s", (char *) NLMSG_DATA(nlh));
	if(nlh->nlmsg_pid != PID)
		PID = nlh->nlmsg_pid;
	char *str = "get string from userspace!";
	int str_len = strlen(str);
	send_msg_to_user(PID, str, str_len);
	if(0)
	{
	struct configList *list_node,*pp;
	struct list_head *list_head;
	int ip_count = 0;
	list_node=&listhead;
	list_for_each(list_head,&list_node->list)//遍历链表
	{
		ip_count++;
		pp=list_entry(list_head, struct configList, list);
		printkHex(pp, sizeof(struct configList)-ip_count, ip_count, "configList");
	}

	}
	return 0;
}

/* Receive messages from netlink socket. */
static void test_nl_rcv_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len) {
			return;
		}

		err = netlink_rcv_msg(skb, nlh);
		if (err) {
			netlink_ack(skb, nlh, err);
		}

		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len) {
			msglen = skb->len;
		}
		skb_pull(skb, msglen);
	}
}


static int kthread_send(void *unused)
{
	while(!kthread_should_stop())
	{
		if(PID)
		{
			struct configList *list_node,*pp;
			struct list_head *list_head;
			int ip_count = 0;
			list_node=&listhead;
			list_for_each(list_head,&list_node->list)//遍历链表
			{
				pp=list_entry(list_head, struct configList, list);
				if(0 == pp->report)
				{	
					send_msg_to_user(PID, pp, sizeof(struct configList));
					pp->report = 1;					
					ip_count++;
				}
				else
					break;
			}
			printk("send %d config\n",ip_count);
		}
		ssleep(1);
	}
	printk(KERN_ALERT "Stopping thread 1 ...\n");
	//do_exit(0);//thread stop immediately
	return 0;
}
static unsigned int nf_hook_in(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int(*okfn)(struct sk_buff*))//钩子点输入
{
	
	struct ethhdr 	*eth = NULL;//Mac头部结构体
	struct iphdr 	*iph = NULL;//IPv4头部（IP头）
	struct tcphdr	*tcph = NULL;//tcp头部
	struct udphdr	*udph = NULL;//tcp头部
	struct config	packetConfig = {0};
	int i;
	if(skb == NULL) 
	{
		printk("skb is NULL!\n");
		return NF_ACCEPT;
	}
	eth = (struct ethhdr *)skb_mac_header(skb);
	if (eth == NULL)
	{
		printk("eth is NULL!\n");
		return NF_ACCEPT;
	}
	else if(ETH_P_IP != ntohs(eth->h_proto))
    {
		return NF_ACCEPT;
	}
	iph =  ip_hdr(skb);
	if (iph == NULL )
	{
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}
	if (IPPROTO_UDP ==	iph->protocol)
	{
		printk("IPPROTO_UDP\n");
		udph = (struct udphdr *) ((u8 *) iph + (iph->ihl << 2)); //important!	
		printk("dest_Mac:%pM, source_Mac:%pM, h_proto:%x\n",eth->h_dest, eth->h_source, ntohs(eth->h_proto));
		printk("version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",\
		iph->version,iph->ihl,iph->tos,ntohs(iph->tot_len),ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13),iph->ttl,iph->protocol,iph->check,&iph->saddr,&iph->daddr);
		printk("source_Port:%d, dest_Port:%d,len:%d check:%d\n",ntohs(udph->source), ntohs(udph->dest), udph->len, udph->check);
		for(i = 0; i < 6; i ++)
		{
			packetConfig.sMac[i] = eth->h_source[i];
			packetConfig.dMac[i] = eth->h_dest[i];
		}
		memcpy((&packetConfig.sIP), &iph->saddr, sizeof(iph->daddr));
		memcpy((&packetConfig.dIP), &iph->daddr, sizeof(iph->daddr));
		memcpy((&packetConfig.sPort), &udph->source, sizeof(udph->source));
		memcpy((&packetConfig.dPort), &udph->dest, sizeof(udph->dest));
		printkHex(&packetConfig, sizeof(packetConfig), 0, "UDP packetConfig");
		{
		struct configList *rcv_data;
		rcv_data=kmalloc(sizeof(struct configList),GFP_ATOMIC);
		memset(rcv_data,0,sizeof(struct configList));
		if(rcv_data == NULL)
			return 1;
		memset(rcv_data, 0, sizeof(struct configList));
		rcv_data->type = 1;
		memcpy(&rcv_data->packetConfig,&packetConfig,sizeof(packetConfig));
		list_add(&rcv_data->list,&listhead.list);
		}
		
	}
	else if (IPPROTO_TCP ==	iph->protocol)
	{
		printk("IPPROTO_TCP\n");
		tcph = (struct tcphdr *) ((u8 *) iph + (iph->ihl << 2)); //important!	
		printk("h_dest:%pM, h_source:%pM, h_proto:%x\n",eth->h_dest, eth->h_source, ntohs(eth->h_proto));
		printk("version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",\
		iph->version,iph->ihl,iph->tos,ntohs(iph->tot_len),ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13),iph->ttl,iph->protocol,iph->check,&iph->saddr,&iph->daddr);
		printk("source_Port:%d, dest_Port:%d, seq:%d, ack_seq:%d, res1:%d,doff:%d, fin:%d, syn:%d, rst:%d, psh:%d, ack:%d, urg:%d, ece:%d,cwr:%d, window:%d, check:%d, urg_ptr:%d\n",\
			ntohs(tcph->source),ntohs(tcph->dest),ntohs(tcph->seq),ntohs(tcph->ack_seq),tcph->res1,tcph->doff,tcph->fin,tcph->syn,tcph->rst,tcph->psh,tcph->ack,tcph->urg,
			tcph->ece,tcph->cwr,ntohs(tcph->window),tcph->check,ntohs(tcph->urg_ptr));
		for(i = 0; i < 6; i ++)
		{
			packetConfig.sMac[i] = eth->h_source[i];
			packetConfig.dMac[i] = eth->h_dest[i];
		}
		memcpy((&packetConfig.sIP), &iph->saddr, sizeof(iph->daddr));
		memcpy((&packetConfig.dIP), &iph->daddr, sizeof(iph->daddr));
		memcpy((&packetConfig.sPort), &tcph->source, sizeof(udph->source));
		memcpy((&packetConfig.dPort), &tcph->dest, sizeof(udph->dest));
		printkHex(&packetConfig, sizeof(packetConfig), 0, "TCP packetConfig");
		{
		struct configList *rcv_data;
		rcv_data=kmalloc(sizeof(struct configList),GFP_ATOMIC);
		memset(rcv_data,0,sizeof(struct configList));
		if(rcv_data == NULL)
			return 1;
		memset(rcv_data, 0, sizeof(struct configList));
		rcv_data->type = 2;
		memcpy(&rcv_data->packetConfig,&packetConfig,sizeof(packetConfig));
		list_add(&rcv_data->list,&listhead.list);
		}
	}
	else
	{
		printk("iph->protocol = %d\n",iph->protocol);
	}
	printk("**********************************************************\n");
	return NF_ACCEPT;
}

static void init_list()
{
	struct configList *rcv_data;
	rcv_data=kmalloc(sizeof(struct configList),GFP_ATOMIC);
	memset(rcv_data,0,sizeof(struct configList));
	list_add(&rcv_data->list,&listhead.list);
}

static int __init test_nl_init(void)
{
	int ret;
	test_nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, 0,test_nl_rcv_skb, NULL, THIS_MODULE);
	if (!test_nl_sock) 
	{
		printk(KERN_ERR "netlink_kernel_create: couldn't create a netlink sock\n");
		return -ENOMEM;
	}
	
	nfhk_local_in.hook = nf_hook_in;
	nfhk_local_in.pf = PF_INET;
	nfhk_local_in.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_in.priority = NF_IP_PRI_FIRST;
	ret = nf_register_hook(&nfhk_local_in);
	if (ret < 0) 
	{
        printk("LOCAL_IN Register Error\n");
        return ret;
    }
	init_list();
	t1 = kthread_create(kthread_send,NULL,"mythread1");
	if(t1)
	{
		printk(KERN_INFO "Thread Created Sucessfully\n");
		wake_up_process(t1);
	}
	else
	{
		printk(KERN_ALERT "Thread Creation Failed\n");
	}
	printk(KERN_INFO "test netlink module init successful\n");

	return 0;
}

static void __exit test_nl_exit(void)
{
	int ret;
	netlink_kernel_release(test_nl_sock);
	
	nf_unregister_hook(&nfhk_local_in);
	
	ret = kthread_stop(t1);
	if(!ret)
		printk(KERN_ALERT "Thread stopped");
	printk(KERN_INFO "test netlink module exit successful\n");
}

module_init(test_nl_init);
module_exit(test_nl_exit);

MODULE_AUTHOR("houjian");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("netlink test module");
