#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
 
#define print_value(x) (x==NULL?"-" : x)
 
static struct mf_rule_struct {
    int in_out;
    char *src_ip;
    char *src_netmask;
    char *src_port;            //default to -1 
    char *dest_ip;
    char *dest_netmask;
    char *dest_port;
    char *proto;
    char *action;
} mf_rule;
 
static struct mf_delete_struct {
    char *cmd;
    char *row;
} mf_delete;

void send_to_proc(char *str)
{
    FILE *pf;
    pf = fopen("/proc/minifirewall", "w");
    if (pf == NULL)  {
        printf("Cannot open /proc/minifirewall for writting\n");
        return;
    } else {
        fprintf(pf, "%s", str);
    }
    fclose(pf);
    return;
}

int get_proto(char* proto) {
    if (strcmp(proto, "ALL") == 0) {
        return 0;
    } else if (strcmp(proto, "TCP") == 0) {
        return 1;
    } else if (strcmp(proto, "UDP") == 0) {
        return 2;
    }
}
 
int get_action(char* action) {
    if (strcmp(action, "BLOCK") == 0) {
	return 0;
    } else if (strcmp(action, "UNBLOCK") == 0) {
	return 1;
    }
}

void send_rule_to_proc()
{
    //printf("send_rule_to_proc\n");
    char a_rule[200];
    sprintf(a_rule, "%u %s %s %s %s %s %s %u %u\n", mf_rule.in_out+1, print_value(mf_rule.src_ip), print_value(mf_rule.src_netmask), print_value(mf_rule.src_port), print_value(mf_rule.dest_ip), print_value(mf_rule.dest_netmask), print_value(mf_rule.dest_port), get_proto(mf_rule.proto), get_action(mf_rule.action));
    //printf("%s\n", a_rule);
    send_to_proc(a_rule);
}
 
void send_delete_to_proc()
{
    //printf("send_delete_to_proc\n");
    char delete_cmd[20];
    sprintf(delete_cmd, "%s%s\n", "d", print_value(mf_delete.row));
    send_to_proc(delete_cmd);
}
 
void print_rule()
{
    FILE *pf;
    char token[20];
    char ch;
    int i = 0;
    printf("in/out    src ip    src mask    src port    dest ip    dest mask     dest port    proto    action\n");
    pf = fopen("/proc/minifirewall", "r");
    if (pf == NULL)  {
        printf("Cannot open /proc/minifirewall for reading\n");
        return;
    } else {
      while (1) {
        while (((ch=fgetc(pf))==' ') || (ch == '\n')) {
            //skip the empty space
        }
        if (ch == EOF) break;
        //in/out
        i = 0;
        token[i++] = ch;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        printf("  %s  ", token);
        if (ch==EOF) break;
        //src ip
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        if (strcmp(token, "-")==0) {
            printf("      %s     ", token);
        } else {
            printf(" %s ", token);
        }
        //src mask
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        if (strcmp(token, "-")==0) {
            printf("     %s         ", token);
        } else {
            printf(" %s ", token);
        }
        if (ch==EOF) break;
        //src port        
        i = 0;
        token[i++] = ' ';
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        printf("%s     ", token);
        if (ch==EOF) break;
        //dest ip
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        if (strcmp(token, "-")==0) {
            printf("      %s     ", token);
        } else {
            printf(" %s ", token);
        }
        if (ch==EOF) break;
        //dest mask
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        if (strcmp(token, "-")==0) {
            printf("      %s             ", token);
        } else {
            printf(" %s ", token);
        }
        if (ch==EOF) break;
        //dest port
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        printf("%s      ", token);
        if (ch==EOF) break;
        //proto
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ')) {
            token[i++] = ch;
        }
        token[i] = '\0';
        printf("    %s    ", token);
        if (ch==EOF) break;
        //action
        i = 0;
        while (((ch=fgetc(pf))!=EOF) && (ch!=' ') && (ch!='\n')) {
            token[i++] = ch;
        }
        token[i] = '\0';  	
        printf(" %s\n", token);
        if (ch==EOF) break;
      }
    }
    fclose(pf);
    return;
    return;
}
 
int main(int argc, char **argv)
{
    int c; int action = 1;    //1: new rule; 2: print; 3: delete
    mf_rule.in_out = -1; mf_rule.src_ip = NULL; mf_rule.src_netmask = NULL; mf_rule.src_port = NULL;
    mf_rule.dest_ip = NULL; mf_rule.dest_netmask = NULL; mf_rule.dest_port = NULL;mf_rule.proto = NULL;
    mf_rule.action = NULL;
    while (1) 
    {
        static struct option long_options[] = 
        {
        /*set a flag*/
            {"in", no_argument, &mf_rule.in_out, 0},
            {"out", no_argument, &mf_rule.in_out, 1},
        /*These options don't set a flag.
            We distinguish them by their indices.*/
            {"print", no_argument, 0, 'o'},
            {"delete", required_argument, 0, 'd'},
            {"srcip", required_argument, 0, 's'},
            {"srcnetmask", required_argument, 0, 'm'},
            {"srcport", required_argument, 0, 'p'},
            {"destip", required_argument, 0, 't'},
            {"destnetmask", required_argument, 0, 'n'},
            {"destport", required_argument, 0, 'q'},
            {"proto", required_argument, 0, 'c'},
            {"action", required_argument, 0, 'a'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long(argc, argv, "od:s:m:p:t:n:q:c:a:", long_options, &option_index);
        /*Detect the end of the options. */
        if (c == -1)
            break;
        action = 1;
        switch (c)
        {
            case 0:
              //printf("flag option: %s, mf_rule.in_out = %d\n", long_options[option_index].name, mf_rule.in_out);
              break;
            case 'o':
                action = 2;    //print
              break;
            case 'd':
              action = 3;       //delete
              mf_delete.cmd = (char *)long_options[option_index].name;
              mf_delete.row = optarg;
              break;
            case 's':
              mf_rule.src_ip = optarg;  //src ip
              break; 
            case 'm':
              mf_rule.src_netmask = optarg; //srcnetmask:
              break;
            case 'p':
              mf_rule.src_port = optarg;    //srcport:
              break;
            case 't':
              mf_rule.dest_ip = optarg;     //destip:
              break;
            case 'n':
              mf_rule.dest_netmask = optarg;    //destnetmask
              break;
            case 'q':
              mf_rule.dest_port = optarg;    //destport
              break;
            case 'c':
              mf_rule.proto = optarg; //proto
              break;
            case 'a':
              mf_rule.action = optarg;//action
              break;
            case '?':
              /* getopt_long printed an error message. */
              break;
            default:
              abort();
        }
    //if (c != 0)
    //    printf("%s = %s\n",  long_options[option_index].name, optarg);
    }
    if (action == 1) {
        send_rule_to_proc();
    } else if (action == 2) {
        print_rule();
    } else if (action == 3) {
        send_delete_to_proc();
    }
    if (optind < argc)
    {
        //printf("non-option ARGV-elements: ");
        while (optind < argc)
        //printf("%s ", argv[optind++]);
        putchar('\n');
    }
}
