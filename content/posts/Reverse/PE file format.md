---
title: "PE 文件分析"
subtitle: ""
date: 2023-08-27T21:15:32+08:00
draft: true
tags: [Reverse, PE, Windows, Note]
categories: [Reverse]

featuredImage: ""
featuredImagePreview: ""
hiddenFromHomePage: false
hiddenFromSearch: false
twemoji: false
lightgallery: true
ruby: true
fraction: true
fontawesome: true
linkToMarkdown: true
rssFullText: false

toc:
  enable: true
  auto: true
code:
  copy: true
  # ...
math:
  enable: true
  # ...
mapbox:
  accessToken: ""
  # ...
share:
  enable: true
  # ...
comment:
  enable: true
  # ...
library:
  css:
    # someCSS = "some.css"
    # 位于 "assets/"
    # 或者
    # someCSS = "https://cdn.example.com/some.css"
  js:
    # someJS = "some.js"
    # 位于 "assets/"
    # 或者
    # someJS = "https://cdn.example.com/some.js"
seo:
  images: []
  # ...
---

# 分析 Portable Executable (PE) 程序

---

## 何為 PE ?

- PE 文件 是 Portable Executable（可移植的可執行文件）的簡寫。 
  包括 EXE、DLL、SYS、COM 都是 PE 文件，且 PE 文件是微軟 Windows 操作系統上的檔案文件。
- 對標 UNIX 系統中的 ELF 文件(.o, .so, 可執行文件...)

![](https://i.imgur.com/bSvVH7i.jpg)

## RAW to RVA

![](https://i.imgur.com/MzMwID5.png)

### 名詞解釋
- RVA(Relative Virtual Address): 相對虛擬地址的偏移(於***記憶體***中)
- VA(virtual Address): 虛擬地址(於***記憶體***中)
- RAW: 在***文件***中的偏移
- PointerToRawData: 該 section 於***文件***中的偏移(定義於 IMAGE_SECTION_HEADER 結構中)
- ImageBase: PE 文件在***記憶體***中的起始位置

### 公式
- $RVA = VA - ImageBase$
    - 解釋: 記憶體中位置減去初始位置等於相對地址
- $RAW - PointerToRawData = RVA - VA$
    - 解釋: 在文件中相對 section base 的偏移 = 在記憶體中相對 section base 的偏移

### Lab

:::warning
#### Q. `RVA = 5000`、`ImageBase = 0x01000000` ，`File Offset = ?`
:::

:::spoiler
#### A. 首先查詢 RVA 所在 section
- (需搭配上圖)
- RVA 5000 位於 .text ()
- 使用公式 RAW = 5000(RVA) - 1000(VA) + 400 (.text 段的 PointerToRawData) = 4400
:::

---

## PE 結構

### DOS Header

```cpp=
typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    USHORT e_magic;         // Magic number
    USHORT e_cblp;          // Bytes on last page of file
    USHORT e_cp;            // Pages in file
    USHORT e_crlc;          // Relocations
    USHORT e_cparhdr;       // Size of header in paragraphs
    USHORT e_minalloc;      // Minimum extra paragraphs needed
    USHORT e_maxalloc;      // Maximum extra paragraphs needed
    USHORT e_ss;            // Initial (relative) SS value
    USHORT e_sp;            // Initial SP value
    USHORT e_csum;          // Checksum
    USHORT e_ip;            // Initial IP value
    USHORT e_cs;            // Initial (relative) CS value
    USHORT e_lfarlc;        // File address of relocation table
    USHORT e_ovno;          // Overlay number
    USHORT e_res[4];        // Reserved words
    USHORT e_oemid;         // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;       // OEM information; e_oemid specific
    USHORT e_res2[10];      // Reserved words
    LONG   e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

#### 重點成員
- `e_magic`: DOS signature (0x4D5A => ASCII: "MZ")
- `e_lfanew`: 指示 NT header 的偏移(根據不同文件有可變值)

---

### DOS stub

- DOS 存根
    - 可選項
    - 大小不定
    - 由代碼跟數據構成
- 用於在 DOS 環境下運行


---

### NT Header

![](https://i.imgur.com/bRLNHwE.png)

~~NT-D (New Type Destroyer)~~

- 主要存放 PE 訊息的地方
- 包含 IMAGE_FILE_HADER (64) 、 IMAGE_OPTIONAL_HEADER32 (64) 等結構

```cpp=
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

- Signature: 簽名，為固定值 0x50450000 ("PE"00)。

#### IMAGE_FILE_HEADER

```cpp=
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

- 俗稱文件頭
    - Machine
        - 紀錄 PE 檔案所存放的機械碼屬於哪一種指令集架構:
            - 每個 CPU 都有唯一的機械碼
            - x86, x64, ARM, etc.
                 ```
                typedef enum _IMAGE_FILE_MACHINE { 
                  UNKNOWN    = 0,
                  I386       = 0x014c,
                  R3000      = 0x0162,
                  R4000      = 0x0166,
                  R10000     = 0x0168,
                  WCEMIPSV2  = 0x0169MIPS,
                  ALPHA      = 0x0184,
                  SH3        = 0x01a2,
                  SH3DSP     = 0x01a3,
                  SH3E       = 0x01a4,
                  SH4        = 0x01a6,
                  SH5        = 0x01a8,
                  ARM        = 0x01c0,
                  THUMB      = 0x01c2,
                  ARM2       = 0x01c4,
                  AM33       = 0x01d3,
                  POWERPC    = 0x01F0,
                  POWERPCFP  = 0x01f1,
                  IA64       = 0x0200,
                  MIPS16     = 0x0266,
                  ALPHA64    = 0x0284,
                  MIPSFPU    = 0x0366,
                  MIPSFPU16  = 0x0466,
                  AXP64      = 0x0284,
                  TRICORE    = 0x0520,
                  CEF        = 0x0CEF,
                  EBC        = 0x0EBC,
                  AMD64      = 0x8664,
                  M32R       = 0x9041,
                  CEE        = 0xC0EE
                } IMAGE_FILE_MACHINE;
                ```

    - NumberOfSections
        - 一個 PE File 通常會有好幾段依代碼、數據、資源切割之塊狀區域， NumberofSections 紀錄了 PE 檔案的區段數量，且必須大於 0 ，當定義與實際情況不同會發生錯誤。

    - TimeDateStamp
        - 紀錄程式編譯時間的時間戳。

    - PointerToSymbolTable
        - 符號表地址，用於除錯，一般為 0 。

    - NumberOfSymbols
        - 如果符號表存在，這邊會記錄符號數量。

    - SizeOfOptionalHeader
        - IMAGE_NT_HEADER 最後一個成員為 IMAGE_OPTIONAL_HEADER32 結構
        - 此變數用來指出其大小
        - 雖然經過編譯大小已確定，但 PE loader 仍需讀取其值識別大小。
            (因為分為 32 bits 和 64 bits 的結構)
    - Characteristics
        - 紀錄了整個 PE 的屬性，包含:
            - Executable (0x0002)
            - Info of redirection
            - 32-bit or not
            - DLL modules (0x2000)
            - [DOC](https://learn.microsoft.com/en-us/previous-versions/mt804320(v=vs.85))

#### IMAGE_OPTIONAL_HEADER32

![](https://i.imgur.com/XOhhEXe.png)

```cpp=

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

- 俗稱可選頭

:::info
補充:
`Optional Header` 不存在於 `Object File (COFF)` ex: `.o`、`.obj`，而是在編譯的連結階段才會由連結器補上。
:::


- AddressOfEntryPoint
    程式碼編譯後，程式的入口點，也就代表當 Program 被作業系統載入時， Process 會從這邊開始執行。
    > 一般來說，入口點會指向 .text section 的函式開頭。

- ImageBase
    記錄了 PE 檔案 mapping 到記憶體上的預設位址
    - EXE 文件通常為 0x400000 或是 0x800000 
    - DLL 則是 0x10000000    


- SizeOfImage
    記錄了當程式處於動態執行階段需要多少虛擬記憶體空間才能存放整個 Image 。

- Section alignment
    在記憶體中的最小單位， 32-bit 的環境下預設大小為 0x1000 bytes 。

- File alignment
    在硬碟中的最小單位， 32-bit 的環境下預設大小為 0x200 bytes 。

        假設有不足 0x200 bytes 的資料要放進塊狀區段，塊狀區段的大小為 0x200 bytes ，如果資料多於預設大小，塊狀區段的大小則為 0x400 bytes 。

- Size of headers
    DOS Header + NT Headers + Section Headers 的大小。

- Subsysyem

    | Value      | Description | Note |
    | ----------- | ----------- | ------ |
    | 1       | Driver       | 系統驅動    |
    | 2       | GUI | 視窗應用程序|
    | 3       | CUI        |  控制台應用程序  |

- NumberOfRvaAndSizes
   指定結構 DataDirectly 陣列的大小
   雖然 DataDirectly 有定義為 16 大小的陣列
   但 PE loader 會讀其值，所以實際大小由此值決定。

- Data directory
     ```cpp=
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD   VirtualAddress;
        DWORD   Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
     ```
     - 可選頭最後一個成員
     - 為結構陣列
     - 存放許多 table 之 RVA 與大小 
         > ex. IAT, EAT, [etc.](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory) 後續會詳細討論

     - VirtualAddress: 該 table 之虛擬地址
         > 註: 此處為 RVA
     - Size: 該 table 之大小

---

### Section Header
- 又名 節區頭
- 定義各節區屬性
- ex. `.code(.text)`, `.data`, `.resource`, etc.
```cpp=
#define IMAGE_SIZEOF_SHORT_NAME    8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

- VirtualSize: 記憶體中該節所占大小
- VirtualAddress: 節區在記憶體中的起始位置(RVA)
- SizeOfRawData: 硬碟中所占大小
- PointerToRawData: 硬碟中之起始位置(RVA)
- [Characteristics](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header): 節區屬性( bit OR )
- Name[IMAGE_SIZEOF_SHORT_NAME]: 8 BYTE，不以 NULL 當結束字元，PE未明確規範僅供參考
    ex. .code/.text


---

### IAT

![](https://i.imgur.com/MKRKG5U.png)

![](https://i.imgur.com/QjPVpXQ.png)


- 全名: Import Address Table(為陣列) 導入地址表
- 用來記錄程序正在使用哪些庫中的哪些函數
- IAT 所提供之機制與 [DLL implicit linking](https://stackoverflow.com/questions/32486699/when-do-these-load-dlls-implicit-linking-vs-explicit-linking) 有關
    - 當調用 API 時會 CALL `.text` section 中的 IAT 記憶體區域，並非直接調用相關地址。
    ex.
    ```asm 
    ;調用 CreateFileW()
    CALL  DWORD PTR DS:[01145140]    ; 01145140 為 IAT 中之地址
    ;而 01145140 存放了 7C812222 此為 CreateFileW() 之實際地址
    ```
:::info
Q. 為何不直接 CALL 7C812222 ?
:::

:::success
A. 
1. 因為編譯程序時不知道需要哪種作業系統環境的 DLL 
        因為版本不同所以實際存放函式的地址也不相同
        有了 IAT 因此只要寫下 `CALL  DWORD PTR DS:[01145140]` 便能在不同環境運行
        執行檔案時 PE loader 會負責抓取 CreateFileW 之位置
2. 因為 DLL relocation ， DLL 的 ImageBase 一般為 `10000000` 若有其他 DLL 需要裝載時則需要重定位分配 ImageBase，所以我們無法直接 Hard Coding
:::

#### IMAGE_IMPORT_DESCRIPTOR
- 紀錄文件需要導入哪些函式庫
- 不位於 PE 頭

```cpp=
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound INT (PIMAGE_THUNK_DATA) 存着INT表地址
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;                           // DLL 名稱
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses) 存着IAT表地址
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

```cpp=
typedef struct _IMAGE_THUNK_DATA {
    union {
         ...
         PDWORD Function;	         
         DWORD Ordinal;
         PIMAGE_IMPORT_BY_NAME AddressOfData;
    }u1;
}IMAGE_THUNK_DATA32;
```
```cpp=
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;         //hint to loader
    BYTE    Name[1];      //name string
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

#### 重點成員:
- OriginalFirstThunk: array of PIMAGE_THUNK_DATA (INT) 之 RVA
- TimeDateStamp: 時間戳
- [ForwarderChain](https://learn.microsoft.com/zh-tw/dotnet/standard/assembly/type-forwarding)
- Name: 該 DLL 名稱
- FirstThunk: IAT 之 RVA

![](https://i.imgur.com/uT43dJx.png)

- PE Loader 加載 IAT 之順序
    - 輸入順序 :
        1. 讀取 IID 的 Name 成員，取得字串 "USER32.DLL”
        2. LoadLibary(”USER32.DLL”);
        3. 讀取 OrigninalFirstThunk ，取得 INT 位置
        4. 使用 IMAGE_IMPORT_BY_NAME 的 Hint 或 Name 取得函數得起始位置。
        5. 取得 IID 的 FirstThunk 成員值， 獲得 IAT 位置。
        6. 把函數位置輸入相應函數之 IAT 中
        7. 重複 4~7 直到 IAT 位置指向值是 NULL

:::info
註: 
- INT、IAT 為 long int array，以 NULL 結束
- INT 中各元素的值為 IMAGE_IMPORT_BT_NAME 的 Pointer(有時 IAT 也擁有相同的值)
- INT、IAT 大小應相同
:::

### EAT

![](https://i.imgur.com/c8n8Kpv.png)

``` c=
typedef struct _IMAGE_EXPORT_DIRECTORY {              
    DWORD   Characteristics;              
    DWORD   TimeDateStamp;               
    WORD    MajorVersion;              
    WORD    MinorVersion;                
    DWORD   Name;                     //DLL 名稱
    DWORD   Base;                     //ordinal base
    DWORD   NumberOfFunctions;            
    DWORD   NumberOfNames;              
    DWORD   AddressOfFunctions;                   
    DWORD   AddressOfNames;         
    DWORD   AddressOfNameOrdinals;                 
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

- 全名: Export Address Table 導出地址表
- 包含 DLL 之入口點與名稱之訊息
- 為調用 API 之端點
> 只有 DLL 有

#### 重點成員:
- NumnerOfFunction: 實際 Export 的函數個數
- NumberOfName: Export 函數中具名的函數個數
- AddressOfFunctions: Export 函數地址之 array (元素個數 = NumberOfFunction)
- AddressOfNames: 函數名稱 array (元素個數 = NumberOfFunction)
- AddressOfNameOrdinals: Ordinal 地址 array (元素個數 = NumberOfFunction)

#### GetProcAddress() 操作原理

- GetProcAddress() 為能從函式庫中獲取其函數地址之 API ，該 API 會利用 EAT 來完成

1. 利用 AddressOfNames 成員跳轉到**函數名稱陣列**
2. **函數名稱陣列** 中儲存著 名稱字串之地址 ，利用 strcmp 查找指定函數名稱(其 index 為 name_index)
3. 利用 AddressOfNameOrdinals 成員跳到 ordinal 陣列
4. 在 ordinal 陣列中 利用 name_index 當作索引找到相應 ordinal 值
5. 利用 AddressOfFunctions 跳到 EAT
6. 在 EAT 中以剛求得之 ordinal 當索引獲取指定函數之起始位置

<div class="boxinfo"> 對於沒有名稱之導出函數，可以利用 Ordinal 查找他們的地址。
從 Ordinal 值中減去 IMAGE_EXPORT_DIRECTORY.Base 成員後得到一個值，使用該值作為 EAT 的索引，即可找到相應函數地址。 </div>
:::info
對於沒有名稱之導出函數，可以利用 Ordinal 查找他們的地址。
從 Ordinal 值中減去 IMAGE_EXPORT_DIRECTORY.Base 成員後得到一個值，使用該值作為 EAT 的索引，即可找到相應函數地址。
:::

---

## Credit
[【逆向】【PE入门】使用PEView分析PE文件](https://blog.csdn.net/qq_43633973/article/details/102378477)
[x86 and amd64 instruction reference](https://www.felixcloutier.com/x86/)
[AT&T Assembly Syntax [ AT&T 汇编语法 ]翻译](https://www.jianshu.com/p/74d54c9d818d)
[Malware Analysis Tutorial 8: PE Header and Export Table](https://www.cnblogs.com/shangdawei/p/4785494.html)
[導出表](https://learn.microsoft.com/zh-cn/cpp/build/exporting-from-a-dll?view=msvc-170)
[01 play with format](https://lief-project.github.io/doc/stable/tutorials/01_play_with_formats.html)
[winnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)
[Where is PE loader in WINDOWS](https://security.stackexchange.com/questions/24785/where-is-the-pe-loader-in-windows)
[學習成為人體 PE Parser](/FC_V7Ye2QCSvQOvoqm5wkw)
[IAT 表](https://www.cnblogs.com/mhpcuit/p/13049764.html)
[PE loader IAT 加載順序](https://ithelp.ithome.com.tw/articles/10297321)
[Exciting Journey Towards Import Address Table (IAT) of an Executable](https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/)
[IAT HOOK](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking)
[MSDN COMPLETE GUIDE](https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN)
