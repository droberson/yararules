rule linux_kernel_module_generic
{
    meta:
        description = "Detects Linux Kernel Modules via known init/unload symbols"
        author = "Daniel Roberson"

    strings:
        $init   = "init_module"
        $clean  = "cleanup_module"

    condition:
        uint32(0) == 0x464c457f and all of them
}

rule linux_kernel_module_loose
{
    meta:
        description = "Likely Linux Kernel Module"
        author = "Daniel Roberson"

    strings:
        $must_have1 = "__this_module"
        $may_have1  = "vermagic="
        $may_have2  = "module_layout"
        $may_have3  = "__init"
        $may_have4  = "__exit"

    condition:
        uint32(0) == 0x464c457f and (any of ($must_have*) and 2 of ($may_have*))
}
