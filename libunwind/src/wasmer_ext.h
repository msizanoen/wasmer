void wasmer_unwind_armehabi_register(void *text_begin, size_t text_size,
                                     void *aeidx_begin, size_t aeidx_size);

void wasmer_unwind_armehabi_deregister(void *text_begin);
