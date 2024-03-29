
def main():
    import idc
    import idautils
    import ida_bytes
    import ida_idaapi
    import ida_nalt
    import ida_ua
    import re
    #确定go语言版本搜索"go1." 或 go version xx.exe

    x64=True
    szint=4;szuint=4;szptr=4
    if x64:
        szint=8;szuint=8;szptr=8


    def get_ptr(addr: int) -> int:
        if szptr==8:
            return ida_bytes.get_64bit(addr)
        else:
            return ida_bytes.get_32bit(addr)


    def get_uint(addr: int) -> int:
        return get_ptr(addr)


    def get_int(addr: int) -> int:
        b = get_ptr(addr).to_bytes(szint, 'little')
        return int.from_bytes(b, byteorder='little', signed=True)


    def search_bytes(hex_bytes: str) -> list:
        patterns = ida_bytes.compiled_binpat_vec_t()
        zero_ea = 0
        pattern_text = hex_bytes
        encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
        err = ida_bytes.parse_binpat_str(patterns, zero_ea, pattern_text, 16, encoding)

        addrlst=[]
        if not err:
            for seg in idautils.Segments():#seg代表段首地址=idc.get_segm_start(seg)
                start=seg
                #print(idc.get_segm_name(seg)+":")
                while (pattern := ida_bytes.bin_search(start, idc.get_segm_end(seg), patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)) != BADADDR:
                    #BIN_SEARCH_FORWARD:search forward for bytes #BIN_SEARCH_NOBREAK:don't check for Ctrl-Break #BIN_SEARCH_NOSHOW:don't show search progress or update screen
                    addrlst.append(pattern)
                    start=pattern+1
        return addrlst


    def to_hex_string(num: int) -> str:
        hex_str = hex(num)[2:]
        hex_lst = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        hex_lst.reverse()
        formatted_str = ' '.join(hex_lst)
        return formatted_str


    def readCString(addr):
        res = ''
        char = ida_bytes.get_byte(addr)
        while  char != 0 and char != 0xff:
            res += chr(char)
            addr += 1
            char = ida_bytes.get_byte(addr)
        return res


    def replace_non_alphanumeric(string):# 将非字母和数字的字符替换为"_"
        pattern = r'[^a-zA-Z0-9]'
        replaced_string = re.sub(pattern, '_', string)
        return replaced_string


    addrlst = search_bytes("?? FF FF FF 00 00 01 08")# pcHeader特征码
    print(list(map(hex,addrlst)))
    if len(addrlst) != 1:
        print("pcHeader addr mismatch")
        return

    '''
    type pcHeader struct {
        magic          uint32  // 0xFFFFFFF1
        pad1, pad2     uint8   // 0,0
        minLC          uint8   // min instruction size
        ptrSize        uint8   // size of a ptr in bytes
        nfunc          int     // number of functions in the module
        nfiles         uint    // number of entries in the file tab
        textStart      uintptr // base for function entry PC offsets in this module, equal to moduledata.text
        funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
        cuOffset       uintptr // offset to the cutab variable from pcHeader
        filetabOffset  uintptr // offset to the filetab variable from pcHeader
        pctabOffset    uintptr // offset to the pctab variable from pcHeader
        pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    }
    '''
    #从pcHeader中读funcnameAddr filetabOAddr pclnOffsetAddr cuOffset
    pcHeaderAddr=addrlst[0]
    base = pcHeaderAddr + 4 + 2 + + 1 + 1
    nfunc = get_ptr(base )#函数数量 nfunc = pclntable_size - 1
    nfiles = get_ptr(base + szint)#文件数量
    print(f"nfunc: {nfunc} nfiles:{nfiles}")
    base += szint + szuint
    #print("base",base)
    textStart = get_ptr(base)
    funcnameAddr = pcHeaderAddr + get_ptr(base + szptr)#函数名
    cutabAddr = pcHeaderAddr + get_ptr(base + szptr*2)
    filetabOAddr = pcHeaderAddr + get_ptr(base + szptr*3)#文件名
    pclnOffsetAddr = pcHeaderAddr + get_ptr(base + szptr*5)#关联函数名与函数地址


    addrlst = search_bytes(to_hex_string(pcHeaderAddr))#pcHeader特征码
    print(list(map(hex,addrlst)))
    if len(addrlst) != 1:
        print("moduledata addr mismatch")
        return

    '''
    type moduledata struct {
        pcHeader     *pcHeader
        funcnametab  []byte
        cutab        []uint32
        filetab      []byte
        pctab        []byte
        pclntable    []byte
        ftab         []functab
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        covctrs, ecovctrs     uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr
        rodata                uintptr
        gofunc                uintptr // go.func.*

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        hasmain uint8 // 1 if module contains the main function, 0 otherwise

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        bad bool // module failed to load and should be ignored

        next *moduledata
    }
    type slice struct{
        array   unsafe.Pointer  //指向一个数组的指针
        len 	int             //当前切片的长度
        cap     int             //当前切片的容量 cap总是大于len
    }
    '''
    #解析moduledata
    moduledata_addr=addrlst[0]
    funcnameAddr2 = get_ptr(moduledata_addr + szptr)#函数名
    cutabAddr2 = get_ptr(moduledata_addr + szptr + (szptr*3))
    filetabOAddr2 = get_ptr(moduledata_addr + szptr + (szptr*3)*2)#文件名
    pclnOffsetAddr2 = get_ptr(moduledata_addr + szptr + (szptr*3)*4)#关联函数名与函数地址

    if funcnameAddr != funcnameAddr2 or cutabAddr != cutabAddr2 or filetabOAddr != filetabOAddr2 or pclnOffsetAddr != pclnOffsetAddr2:
        print(funcnameAddr, funcnameAddr2, cutabAddr, cutabAddr2, filetabOAddr, filetabOAddr2, pclnOffsetAddr, pclnOffsetAddr2)
        print("funcnameAddr/cutabAddr/filetabOAddr/pclnOffsetAddr addr mismatch")
        return

    pclntable_size = idc.get_qword(moduledata_addr + 8 + ((szptr*3) * 5) + szptr)
    print(f"pclnOffsetAddr:{hex(pclnOffsetAddr)} pclntable_size: {hex(pclntable_size)}")
    #funcnum = 0
    for i in range(pclntable_size):
        #go中数据组织形式: functab数组 + _func数组
        '''
        type functab struct {
	        entryoff uint32 // relative to runtime.text
	        funcoff  uint32 // 相对pclnOffsetAddr的偏移
        }
        '''
        base = pclnOffsetAddr + (i * 8)
        #print(base,i)
        functab_entryOff = ida_bytes.get_32bit(base)
        _funcAddr = pclnOffsetAddr + ida_bytes.get_32bit(base + 4)

        _func_entryOff = ida_bytes.get_32bit(_funcAddr)
        if _func_entryOff != functab_entryOff: #_func.entryOff == functab.entryoff
            print(i, hex(base), _func_entryOff, functab_entryOff)
            break
        '''
        type _func struct {
            entryOff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
            nameOff  int32  // function name, as index into moduledata.funcnametab.

            args        int32  // in/out args size
            deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

            pcsp      uint32
            pcfile    uint32
            pcln      uint32
            npcdata   uint32
            cuOffset  uint32 // runtime.cutab offset of this function's CU
            startLine int32  // line number of start of function (func keyword/TEXT directive)
            funcID    funcID // set for certain special runtime functions
            flag      funcFlag
            _         [1]byte // pad
            nfuncdata uint8   // must be last, must end on a uint32-aligned boundary

            // The end of the struct is followed immediately by two variable-length
            // arrays that reference the pcdata and funcdata locations for this
            // function.

            // pcdata contains the offset into moduledata.pctab for the start of
            // that index's table. e.g.,
            // &moduledata.pctab[_func.pcdata[_PCDATA_UnsafePoint]] is the start of
            // the unsafe point table.
            //
            // An offset of 0 indicates that there is no table.
            //
            // pcdata [npcdata]uint32

            // funcdata contains the offset past moduledata.gofunc which contains a
            // pointer to that index's funcdata. e.g.,
            // *(moduledata.gofunc +  _func.funcdata[_FUNCDATA_ArgsPointerMaps]) is
            // the argument pointer map.
            //
            // An offset of ^uint32(0) indicates that there is no entry.
            //
            // funcdata [nfuncdata]uint32
        }
        '''
        funcname = readCString(funcnameAddr + ida_bytes.get_32bit(_funcAddr + 4))
        pcfile = ida_bytes.get_32bit(_funcAddr + 4*5)#fileno
        fileoff = ida_bytes.get_32bit(cutabAddr + pcfile)
        filepath=''
        #if fileoff != 0xFFFFFFFF:
        #    print(f"fileoff: {hex(fileoff)}")
        #    filepath = readCString(filetabOAddr + fileoff*4)

        #print(hex(textStart + _func_entryOff), funcname, replace_non_alphanumeric(funcname))
        idafuncname = replace_non_alphanumeric(funcname)
        real_func_addr = textStart + _func_entryOff
        with open("./func_sym.txt", "a") as f:
            f.write(hex(real_func_addr) + " : " + funcname + "  " + idafuncname + "  " + filepath + "\n")
        # if idafuncname in map(idc.get_func_name, idautils.Functions()):
        #     funcnum+=1
        #     idafuncname+='_'+str(funcnum)
        j = 0
        idafuncname_temp = idafuncname
        while idc.get_name_ea_simple(idafuncname_temp) != idc.BADADDR:
            print("重复函数名", idafuncname_temp)
            j+=1
            idafuncname_temp = idafuncname + '_' + str(j)
        print(hex(real_func_addr), idafuncname_temp)
        #解决ida分析为字节数组后不能直接在其内部重命名的问题
        #todo can't rename byte as 'runtime_main_func2' because this byte can't have a name (it is a tail byte).
        if not ida_bytes.is_code(ida_bytes.get_flags(real_func_addr)):#判断此地址不是代码
            #不是代码则创建
            print("anonymous data", hex(real_func_addr))
            ida_bytes.del_items(real_func_addr)
            ida_ua.create_insn(real_func_addr)

        if idc.set_name(real_func_addr, idafuncname_temp) == 0:
            print("rename fail", hex(real_func_addr))
        else:
            print("rename success", hex(real_func_addr))
    #读取存储的文件信息
    off=0
    for i in range(nfiles):
        text = readCString(filetabOAddr + off)
        off+=len(text)+1
        print(text)

    print(hex(filetabOAddr), hex(off))


main()
