#[cfg(test)]
mod tests {
    use wabt::wat2wasm;
    //use wasmer_clif_backend::CraneliftCompiler;
    use wasmer_llvm_backend::LLVMCompiler;
    use wasmer_runtime_core::{
        error::{CallError, RuntimeError},
        import::ImportObject,
    };

    // The semantics of stack overflow are documented at:
    // https://webassembly.org/docs/semantics/#stack-overflow
    #[test]
    #[ignore]
    fn test_stack_overflow() {
        let module_str = r#"(module
      (type (;0;) (func))
      (func (;0;) (type 0)
        i32.const 0
        call_indirect (type 0))
      (table (;0;) 1 anyfunc)
      (export "stack-overflow" (func 0))
      (elem (;0;) (i32.const 0) 0))
    "#;
        let wasm_binary = wat2wasm(module_str.as_bytes()).expect("WAST not valid or malformed");
        let module = wasmer_runtime_core::compile_with(&wasm_binary[..], &LLVMCompiler::new())
            .expect("WASM can't be compiled");
        let instance = module
            .instantiate(&ImportObject::new())
            .expect("WASM can't be instantiated");
        let result = instance.call("stack-overflow", &[]);

        match result {
            Err(err) => match err {
                CallError::Runtime(RuntimeError::Trap { msg }) => {
                    assert!(!msg.contains("segmentation violation"));
                    assert!(!msg.contains("bus error"));
                }
                _ => unimplemented!(),
            },
            Ok(_) => panic!("should fail with error due to stack overflow"),
        }
    }
}
