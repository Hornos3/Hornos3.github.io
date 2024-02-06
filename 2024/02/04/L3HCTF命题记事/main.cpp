//
// Created by root on 24-1-6.
//
#include "hashmap.cpp"
#include <random>
#include <unistd.h>
#include <sys/mman.h>

unsigned coin = 0;
SwissTable<size_t, size_t> *hashmap;
unsigned char* field;
char* page;
bool have_dream = false;

void banner(){
    setbuf(stdin, nullptr);
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    puts("██╗     ██████╗ ██╗  ██╗ ██████╗████████╗███████╗\n"
         "██║     ╚════██╗██║  ██║██╔════╝╚══██╔══╝██╔════╝\n"
         "██║      █████╔╝███████║██║        ██║   █████╗  \n"
         "██║      ╚═══██╗██╔══██║██║        ██║   ██╔══╝  \n"
         "███████╗██████╔╝██║  ██║╚██████╗   ██║   ██║     \n"
         "╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝     \n"
         "                                                 ");
}

int read_remote(char* buf, size_t size){
    for(int i=0; i<size; i++){
        read(0, &buf[i], 1);
        if(buf[i] == '\n'){
            buf[i] = '\0';
            return i;
        }
    }
    return size;
}

void init(){
    field = (unsigned char*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    for(int i=0; i<0x1000; i++)
        field[i] = (unsigned char)random();

    puts("You are a treasure hunter hoping to dig out as much gold as you can.");
    puts("Today, you go to a desert, where as said buried many gold coins.");
    puts("For more convenience, people divided this desert into pieces, each piece labelled with a number(0 to 0xFFF).");
    puts("As there is limited water, you cannot dig for a long time.");
    puts("Every day, you can only dig or detect one piece of this desert.");
    puts("If you choose to dig, you can find all the coins in this piece (if there exists any), but in a risk of quicksand.");
    puts("If you choose to detect, you can find out whether this piece is safe to dig, avoiding losing your life.");
    puts("To start your exploration, I draw an incomplete map of this desert which contains danger info of some pieces.");
    puts("Drawing...");

    hashmap = new SwissTable<size_t, size_t>();
    while(hashmap->size() < 0x1C){
        unsigned key = random() % 0x1000;
        bool value = random() % 2;
        if(hashmap->entry(key))
            continue;
        printf("place %u: %ssafe\n", key, value ? "" : "un");
        hashmap->insert(key, value);
    }

    puts("Now you got all the info of my map.");
    puts("Ready to roll!");
}

void get_or_put(size_t idx){
    puts("Mining...");
    if(field[idx] == 0)
        printf("No! There is no gold here.\n");
    else
        printf("Congratulations! we discovered %d gold coin(s)!\n", field[idx]);
    puts("Captain! we have 2 choices now. Bury more coins or get some?(b for bury and g for get)");
    char user_choice;
    read_remote(&user_choice, 1);
    if(user_choice == 'b'){
        if(coin == 0){
            puts("We have no coin now...");
            return;
        }
        puts("How many to bury?");
        unsigned bury_num = 0;
        std::cin >> bury_num;
        if(bury_num > coin){
            puts("We need more gold...");
            return;
        }
        if(bury_num + field[idx] > 255){
            puts("Listen, captain, we don't want other people know we are burying gold here, "
                 "if you want to bury that much, anyone can see the gold on the ground ----"
                 "we cannot bury so much!");
            return;
        }
        puts("Alright! let's work, lads!");
        field[idx] += bury_num;
        coin -= bury_num;
    }else if(user_choice == 'g'){
        if(field[idx] == 0){
            puts("No coin here...");
            return;
        }
        puts("How many to get?");
        unsigned get_num = 0;
        std::cin >> get_num;
        if(get_num > field[idx]){
            puts("There is not so many for us to get...");
            return;
        }
        field[idx] -= get_num;
        coin += get_num;
    }else{
        puts("What did you say? The wind is blowing so heavily and I can't understand!");
        return;
    }
}

void shop(){
    if(coin < 30)
        return;
    puts("Welcome to my bar! I have a magic stuff -- super-dream, if you buy it, you will hear the god whispering to you,"
         " telling you some mysterious things.");
    puts("Buy?(y for yes)");
    char user_choice;
    read_remote(&user_choice, 1);
    if(user_choice == 'y' or user_choice == 'Y'){
        puts("I bet you won't regret!");
        coin -= 30;
        have_dream = true;
    }
}

int main() {
    void* _ = malloc(0x400);
    banner();
    init();
    free(_);
    while(true) {
        puts("Today, where are we going, captain?");
        size_t idx;
        std::cin >> idx;
        if(!hashmap->entry(idx)){
            puts("Oops! Your map doesn't contain info about this place, out of security, we'd better not go there.");
            continue;
        }
        if(!(*hashmap)[idx]){
            puts("Ugh! This place has some dangerous things, I can't let you risk your life, my dear captain!");
            continue;
        }

        get_or_put(idx);

        puts("Captain! Write something to record our achievements!");
        printf("Content length: ");
        unsigned length;
        std::cin >> length;
        if(length > 0x1000){
            puts("Uh-oh, you cannot write so many words in one page!");
            continue;
        }
        page = (char*)malloc(length);
        printf("Content: ");
        size_t bytes_read = read(0, page, length + 10);
        printf("Read %#zx bytes.\n", bytes_read);
        free(page);

        shop();
        if(have_dream){
            printf("\033[1;31mHello, my boy! I'm your god. I'll give you a mysterious number, if you know how to use "
                   "this number, You can then get a thing called flag: %p\033[0m", hashmap);
            printf("\033[1;31mI know you've written many words on your legendary diary, "
                 "but now I allow you to write in a unique way. Every time when someone opens this diary, your words "
                 "will burst out with a beam of light! Now tell me where you want to write: \033[0m");
            unsigned page_off = 0;
            std::cin >> page_off;
            if(page_off > hashmap->capacity())
                puts("Oh, I have my limit, greedy man!");
            else{
                puts("Write: ");
                read(0, &((*hashmap->ctr_bytes)[page_off]), 1);        // allow player to change control bytes
            }
            have_dream = false;
        }

        puts("Do you get what you want, captain?(y to end exploration)");
        char user_choice;
        read_remote(&user_choice, 1);
        if(user_choice == 'y' or user_choice == 'Y')
            break;
    }
    printf("We got %u coins for total! They must be very precious!", coin);
}
