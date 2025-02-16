/*


*/


#include <stdio.h>
#include <string.h>
#include <unistd.h>

int a = 2;
char* str = "string";
char buffer[3];
int counter = 0x20000;

int other_function(){
    // write(1,str,6);
    puts(str);
    return 1;
}

void function_call(int value) {
    // Math operations
    value = a * value;
    a = value / a;
    a += 123;

    int mod_number = value % 7;
    int len = strlen(str);
    len -= 2;

    counter = counter >> len;
    counter = counter | mod_number;
    counter = counter & mod_number;
    counter = counter ^ mod_number;

    // Memory accesses have interesting representations in assembly
    for(int i = 0; i < sizeof(buffer); i++){
        buffer[i] = i;
    }
    int b = buffer[1];

    for(int i = sizeof(buffer) - 1; i > 0; --i){
        buffer[i] = i + 1;
    }
    int c = buffer[1];

    // Try some branching
    if (c > b) { // true
        b++;
        if(value <= c){
            c++;
        } else {
            // This path gets taken at runtime
            other_function();
            value++;
        }
    }

    // printf("Hello world! %d, %d, %d", a + b + c, mod_number, len);
};

int main(int argc, char const* argv[])
{
    function_call(123);
    return 0;
}


