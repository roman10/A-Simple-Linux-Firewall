#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define PROCF_MAX_SIZE 1024
#define PROCF_NAME "minifirewall"
 
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux minifirewall");
MODULE_AUTHOR("Liu Feipeng/roman10");

//the structure used for procfs
static struct proc_dir_entry *mf_proc_file;
unsigned long procf_buffer_pos;
char *procf_buffer;

//the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

 
/*structure for firewall policies*/
struct mf_rule_desp {
    unsigned char in_out;
    char *src_ip;
    char *src_netmask;
    char *src_port;
    char *dest_ip;
    char *dest_netmask;
    char *dest_port;
    unsigned char proto;
    unsigned char action;
};
 
 
/*structure for firewall policies*/
struct mf_rule {
    unsigned char in_out;        //0: neither in nor out, 1: in, 2: out
    unsigned int src_ip;        //
    unsigned int src_netmask;        //
    unsigned int src_port;        //0~2^32
    unsigned int dest_ip;
    unsigned int dest_netmask;
    unsigned int dest_port;
    unsigned char proto;        //0: all, 1: tcp, 2: udp
    unsigned char action;        //0: for block, 1: for unblock
    struct list_head list;
};
 
static struct mf_rule policy_list;
 
unsigned int port_str_to_int(char *port_str) {
    unsigned int port = 0;    
    int i = 0;
    if (port_str==NULL) {
        return 0;
    } 
    while (port_str[i]!='\0') {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }
    return port;
}

void port_int_to_str(unsigned int port, char *port_str) {
    sprintf(port_str, "%u", port);
}
 
unsigned int ip_str_to_hl(char *ip_str) {
    /*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0; 
    }
    memset(ip_array, 0, 4);
    while (ip_str[i]!='.') {
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='\0') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    //printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
    return ip;
}

void ip_hl_to_str(unsigned int ip, char *ip_str) {
    /*convert hl to byte array first*/
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);
    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}
 
/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
    unsigned int tmp = ntohl(ip);    //network to host long
    int cmp_len = 32;
    int i = 0, j = 0;
    printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);
    if (mask != 0) {
       cmp_len = 0;
       for (i = 0; i < 32; ++i) {
         if (mask & (1 << (32-1-i)))
           cmp_len++;
      else
         break;
       }
    }
    /*compare the two IP addresses for the first cmp_len bits*/
    for (i = 31, j = 0; j < cmp_len; --i, ++j) {
        if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
            printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
            return false;
        }
    }
    return true;
}
 
void add_a_rule(struct mf_rule_desp* a_rule_desp) {
    struct mf_rule* a_rule;
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if (a_rule == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }
    a_rule->in_out = a_rule_desp->in_out;
    if (strcmp(a_rule_desp->src_ip, "-") != 0) 
        a_rule->src_ip = ip_str_to_hl(a_rule_desp->src_ip);
    else
        a_rule->src_ip = NULL;
    if (strcmp(a_rule_desp->src_netmask, "-") != 0)
        a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
    else
        a_rule->src_netmask = NULL;
    if (strcmp(a_rule_desp->src_port, "-") != 0)
        a_rule->src_port = port_str_to_int(a_rule_desp->src_port);
    else 
        a_rule->src_port = NULL;
    if (strcmp(a_rule_desp->dest_ip, "-") != 0)
        a_rule->dest_ip = ip_str_to_hl(a_rule_desp->dest_ip);
    else 
        a_rule->dest_ip = NULL;
    if (strcmp(a_rule_desp->dest_netmask, "-") != 0)
        a_rule->dest_netmask = ip_str_to_hl(a_rule_desp->dest_netmask);
    else 
        a_rule->dest_netmask = NULL;
    if (strcmp(a_rule_desp->dest_port, "-") != 0)
        a_rule->dest_port = port_str_to_int(a_rule_desp->dest_port);
    else 
        a_rule->dest_port = NULL;
    a_rule->proto = a_rule_desp->proto;
    a_rule->action = a_rule_desp->action;
    printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, dest_ip=%u, dest_netmask=%u, dest_port=%u, proto=%u, action=%u\n", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
    INIT_LIST_HEAD(&(a_rule->list));
    list_add_tail(&(a_rule->list), &(policy_list.list));
}

void init_mf_rule_desp(struct mf_rule_desp* a_rule_desp) {
    a_rule_desp->in_out = 0;
    a_rule_desp->src_ip = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->src_netmask = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->src_port = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->dest_ip = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->dest_netmask = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->dest_port = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->proto = 0;
    a_rule_desp->action = 0;
}
 
void delete_a_rule(int num) {
    int i = 0;
    struct list_head *p, *q;
    struct mf_rule *a_rule;
    printk(KERN_INFO "delete a rule: %d\n", num);
    list_for_each_safe(p, q, &policy_list.list) {
        ++i;
        if (i == num) {
            a_rule = list_entry(p, struct mf_rule, list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}

int procf_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
    int ret;
    struct mf_rule *a_rule;
    char token[20];
    printk(KERN_INFO "procf_read (/proc/%s) called \n", PROCF_NAME);
    if (offset > 0) {
        printk(KERN_INFO "eof is 1, nothing to read\n");
        *eof = 1;
        return 0;
    } else {
        procf_buffer_pos = 0;
        ret = 0;
        list_for_each_entry(a_rule, &policy_list.list, list) {
            //in or out
            if (a_rule->in_out==1) {
                strcpy(token, "in");
            } else if (a_rule->in_out==2) {
                strcpy(token, "out");
            }
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //src ip
            if (a_rule->src_ip == NULL) {
                strcpy(token, "-");
            } else {
                ip_hl_to_str(a_rule->src_ip, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //src netmask
            if (a_rule->src_netmask==NULL) {
                strcpy(token, "-");
            } else {
                ip_hl_to_str(a_rule->src_netmask, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //src port
            if (a_rule->src_port==0) {
                strcpy(token, "-");
            } else {
                port_int_to_str(a_rule->src_port, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //dest ip
            if (a_rule->dest_ip==NULL) {
                strcpy(token, "-");
            } else {
                ip_hl_to_str(a_rule->dest_ip, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //dest netmask
            if (a_rule->dest_netmask==NULL) {
                strcpy(token, "-");
            } else {
                ip_hl_to_str(a_rule->dest_netmask, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //dest port
            if (a_rule->dest_port==0) {
                strcpy(token, "-");
            } else {
                port_int_to_str(a_rule->dest_port, token);
            } 
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //protocol
            if (a_rule->proto==0) {
                strcpy(token, "ALL");
            } else if (a_rule->proto==1) {
                strcpy(token, "TCP");
            }  else if (a_rule->proto==2) {
                strcpy(token, "UDP");
            }
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //action
            if (a_rule->action==0) {
                strcpy(token, "BLOCK");
            } else if (a_rule->action==1) {
                strcpy(token, "UNBLOCK");
            }
            printk(KERN_INFO "token: %s\n", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, "\n", 1);
            procf_buffer_pos++;
        }
        //copy from procf_buffer to buffer
        printk(KERN_INFO "procf_buffer_pos: %ld\n", procf_buffer_pos);
        memcpy(buffer, procf_buffer, procf_buffer_pos);
        ret = procf_buffer_pos;
    }
    return ret;
}

int procf_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
   int i, j;
   struct mf_rule_desp *rule_desp;
   printk(KERN_INFO "procf_write is called.\n");
   /*read the write content into the storage buffer*/
   procf_buffer_pos = 0;
   printk(KERN_INFO "pos: %ld; count: %ld\n", procf_buffer_pos, count);
   if (procf_buffer_pos + count > PROCF_MAX_SIZE) {
       count = PROCF_MAX_SIZE-procf_buffer_pos;
   } 
   if (copy_from_user(procf_buffer+procf_buffer_pos, buffer, count)) {
       return -EFAULT;
   }
   if (procf_buffer[procf_buffer_pos] == 'p') {
       //print command
       return 0;
   } else if (procf_buffer[procf_buffer_pos] == 'd') {
       //delete command
       i = procf_buffer_pos+1; j = 0;
       while ((procf_buffer[i]!=' ') && (procf_buffer[i]!='\n') ) {
           printk(KERN_INFO "delete: %d\n", procf_buffer[i]-'0');
           j = j*10 + (procf_buffer[i]-'0');
           ++i;
       }
       printk(KERN_INFO "delete a rule: %d\n", j);
       delete_a_rule(j);
       return count;
   }
   /*add a new policy according to content int the storage buffer*/
   rule_desp = kmalloc(sizeof(*rule_desp), GFP_KERNEL);
   if (rule_desp == NULL) {
       printk(KERN_INFO "error: cannot allocate memory for rule_desp\n");
       return -ENOMEM;
   }
   init_mf_rule_desp(rule_desp);
   
   /**fill in the content of the new policy **/
   /***in_out***/
   i = procf_buffer_pos; j = 0;
   if (procf_buffer[i]!=' ') {
       rule_desp->in_out = (unsigned char)(procf_buffer[i++] - '0');
   }
   ++i;
   printk(KERN_INFO "in or out: %u\n", rule_desp->in_out);
   /***src ip***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->src_ip[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->src_ip[j] = '\0';
   printk(KERN_INFO "src ip: %s\n", rule_desp->src_ip);
   /***src netmask***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->src_netmask[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->src_netmask[j] = '\0';
   printk(KERN_INFO "src netmask: %s\n", rule_desp->src_netmask);
   /***src port number***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->src_port[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->src_port[j] = '\0';
   printk(KERN_INFO "src_port: %s\n", rule_desp->src_port);
   /***dest ip***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->dest_ip[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->dest_ip[j] = '\0';
   printk(KERN_INFO "dest ip: %s\n", rule_desp->dest_ip);
   /***dest netmask***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->dest_netmask[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->dest_netmask[j] = '\0';
   printk(KERN_INFO "dest netmask%s\n", rule_desp->dest_netmask);
   /***dest port***/
   j = 0;
   while (procf_buffer[i]!=' ') {
       rule_desp->dest_port[j++] = procf_buffer[i++];
   }
   ++i;
   rule_desp->dest_port[j] = '\0';
   printk(KERN_INFO "dest port: %s\n", rule_desp->dest_port);
   /***proto***/
   j = 0;
   if (procf_buffer[i]!=' ') {
       if (procf_buffer[i] != '-')
           rule_desp->proto = (unsigned char)(procf_buffer[i++]-'0');
       else
           ++i;
   }
   ++i;
   printk(KERN_INFO "proto: %d\n", rule_desp->proto);
   /***action***/
   j = 0;
   if (procf_buffer[i]!=' ') {
       if (procf_buffer[i] != '-')
           rule_desp->action = (unsigned char)(procf_buffer[i++]-'0');
       else
           ++i;
   }
   ++i;
   printk(KERN_INFO "action: %d\n", rule_desp->action);
   add_a_rule(rule_desp);
   kfree(rule_desp);
   printk(KERN_INFO "--------------------\n");
   return count;
}

//the hook function itself: regsitered for filtering outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
   /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct mf_rule *a_rule;
   char src_ip_str[16], dest_ip_str[16];
   int i = 0;
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   /***get src and dest port number***/
   if (ip_header->protocol==17) {
       udp_header = (struct udphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
   }
   ip_hl_to_str(ntohl(src_ip), src_ip_str);
   ip_hl_to_str(ntohl(dest_ip), dest_ip_str);
   printk(KERN_INFO "OUT packet info: src ip: %u = %s, src port: %u; dest ip: %u = %s, dest port: %u; proto: %u\n", src_ip, src_ip_str, src_port, dest_ip, dest_ip_str, dest_port, ip_header->protocol); 
   //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one
   list_for_each(p, &policy_list.list) {
       i++;
       a_rule = list_entry(p, struct mf_rule, list);
       //printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
       //if a rule doesn't specify as "out", skip it
       if (a_rule->in_out != 2) {
           printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", i, a_rule->in_out);
           continue;
       } else {
           //check the protocol
           if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
               printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
               continue;
           } else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
               printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
               continue;
           }
           //check the ip address
           if (a_rule->src_ip==0) {
              //rule doesn't specify ip: match
           } else {
              if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                  printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }
           }
           if (a_rule->dest_ip == 0) {
               //rule doesn't specify ip: match
           } else {
               if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
                   printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
                   continue;
               }
           }
           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
               continue;
           }
           if (a_rule->dest_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dest_port!=a_rule->dest_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
   	       printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {
               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
   	       printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }
       }
   }
   printk(KERN_INFO "no matching is found, accept the packet\n");
   printk(KERN_INFO "---------------------------------------\n");
   return NF_ACCEPT;			
}


//the hook function itself: registered for filtering incoming packets
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
   /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct mf_rule *a_rule;
   char src_ip_str[16], dest_ip_str[16];
   int i = 0;
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   /***get src and dest port number***/
   if (ip_header->protocol==17) {
       udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
   }
   ip_hl_to_str(ntohl(src_ip), src_ip_str);
   ip_hl_to_str(ntohl(dest_ip), dest_ip_str);
   printk(KERN_INFO "IN packet info: src ip: %u = %s, src port: %u; dest ip: %u = %s, dest port: %u; proto: %u\n", src_ip, src_ip_str, src_port, dest_ip, dest_ip_str, dest_port, ip_header->protocol); 
   //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one
   list_for_each(p, &policy_list.list) {
       i++;
       a_rule = list_entry(p, struct mf_rule, list);
//printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
       //if a rule doesn't specify as "in", skip it
       if (a_rule->in_out != 1) {
           printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n", i, a_rule->in_out);
           continue;
       } else {
           //check the protocol
           if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
               printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
               continue;
           } else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
               printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
               continue;
           }
           //check the ip address
           if (a_rule->src_ip==0) {
              //
           } else {
              if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                  printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }
           }
           if (a_rule->dest_ip == 0) {
               //
           } else {
               if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
                  printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);                  
                  continue;
               }
           }
           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
               continue;
           }
           if (a_rule->dest_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dest_port!=a_rule->dest_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
               printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {
               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
               printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }
       }
   }
   printk(KERN_INFO "no matching is found, accept the packet\n");
   printk(KERN_INFO "---------------------------------------\n");
   return NF_ACCEPT;				
}
 
/* Initialization routine */
int init_module() {
    printk(KERN_INFO "initialize kernel module\n");
    procf_buffer = (char *) vmalloc(PROCF_MAX_SIZE);
    INIT_LIST_HEAD(&(policy_list.list));
    mf_proc_file = create_proc_entry(PROCF_NAME, 0644, NULL);
    if (mf_proc_file==NULL) {
        printk(KERN_INFO "Error: could not initialize /proc/%s\n", PROCF_NAME);
        return -ENOMEM; 
    } 
    mf_proc_file->read_proc = procf_read;
    mf_proc_file->write_proc = procf_write;
    printk(KERN_INFO "/proc/%s is created\n", PROCF_NAME);
    /* Fill in the hook structure for incoming packet hook*/
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);         // Register the hook
    /* Fill in the hook structure for outgoing packet hook*/
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);    // Register the hook
    return 0;
}
 
/* Cleanup routine */
void cleanup_module() {
    struct list_head *p, *q;
    struct mf_rule *a_rule;
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
    printk(KERN_INFO "free policy list\n");
    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free one\n");
        a_rule = list_entry(p, struct mf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
    remove_proc_entry(PROCF_NAME, NULL);
    printk(KERN_INFO "kernel module unloaded.\n");
 
}
