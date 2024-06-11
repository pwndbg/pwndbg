void break_here(void) {}
void configure_heap_layout(void);

int main(void)
{
    configure_heap_layout();

    break_here();

}

void configure_heap_layout(void)
{

    // Request 1024 bytes so it's allocated by 21st bin with spacing 128 of type small
    void *ptr = malloc(1024);

    free(ptr);
}
