/*
 * Pyrph Native Runtime — _pyrph.so
 * ==================================
 * Loaded via memfd_create (never written to disk).
 *
 * Exports:
 *   decrypt_exec(enc, key_frags, step, inv_perm, orig_len,
 *                nonce, fake_file, globs)
 *       → legacy path: decrypt AES+XOR+perm → marshal.loads → PyEval_EvalCode
 *
 *   decrypt_exec_vm(enc, key_frags, step, inv_perm, orig_len,
 *                   nonce, opmap[256], consts, names, fake_file, globs)
 *       → v2 path: decrypt → run Pyrph C VM (no PyEval_EvalCode)
 *
 *   version() → opaque int (0x50595246 = 'PYRF')
 *
 * Security:
 *   - Whitebox key: reconstructed from _KD[_KP[i]]^_KM[i] arrays
 *     (injected at compile time via -include wb_key.h)
 *   - Anti-debug: ptrace, /proc/self/status, timing check
 *   - All sensitive buffers wiped with secure_zero() after use
 *   - Symbols stripped: only PyInit__pyrph visible
 *   - Stack protector + FORTIFY_SOURCE
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* Whitebox key header injected at compile time.
 * Without PYRPH_V2: fall back to a default key (testing only). */
#ifndef PYRPH_V2
#  define _KD_DEFAULT {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,\
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,\
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
static const uint8_t _KD[64] = _KD_DEFAULT;
static const uint8_t _KP[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t _KM[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
#endif

#pragma GCC visibility push(hidden)

typedef unsigned char u8;
typedef unsigned int  u32;
#define xtime(x) (((x)<<1)^(((x)>>7)*0x1b))

/* ── Secure zero ─────────────────────────────────────────────────────── */
static void _zero(void *p, size_t n){
    volatile u8 *v=(volatile u8*)p; while(n--)*v++=0;
}

/* ── Reconstruct AES key from WB arrays ──────────────────────────────── */
static void _get_key(u8 key[16]){
    for(int i=0;i<16;i++) key[i]=_KD[_KP[i]]^_KM[i];
}

/* ── AES-128 CTR ─────────────────────────────────────────────────────── */
static const u8 _sb[256]={
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static u32 _sw(u32 w){return((u32)_sb[(w>>24)&0xff]<<24)|((u32)_sb[(w>>16)&0xff]<<16)|((u32)_sb[(w>>8)&0xff]<<8)|(u32)_sb[w&0xff];}
static u32 _rw(u32 w){return(w<<8)|(w>>24);}
static void _kx(const u8 k[16],u32 rk[44]){
    static const u32 rc[10]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000};
    for(int i=0;i<4;i++) rk[i]=((u32)k[4*i]<<24)|((u32)k[4*i+1]<<16)|((u32)k[4*i+2]<<8)|(u32)k[4*i+3];
    for(int i=4;i<44;i++){u32 t=rk[i-1];if(i%4==0)t=_sw(_rw(t))^rc[i/4-1];rk[i]=rk[i-4]^t;}
}
static void _enc(const u8 in[16],u8 out[16],const u32 rk[44]){
    u8 s[16];memcpy(s,in,16);
    for(int i=0;i<4;i++){s[4*i]^=(rk[i]>>24)&0xff;s[4*i+1]^=(rk[i]>>16)&0xff;s[4*i+2]^=(rk[i]>>8)&0xff;s[4*i+3]^=rk[i]&0xff;}
    for(int r=1;r<=10;r++){
        for(int i=0;i<16;i++)s[i]=_sb[s[i]];
        u8 t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t;t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if(r<10){for(int c=0;c<4;c++){u8 a0=s[c],a1=s[c+4],a2=s[c+8],a3=s[c+12];s[c]=xtime(a0)^xtime(a1)^a1^a2^a3;s[c+4]=a0^xtime(a1)^xtime(a2)^a2^a3;s[c+8]=a0^a1^xtime(a2)^xtime(a3)^a3;s[c+12]=xtime(a0)^a0^a1^a2^xtime(a3);}}
        int b=r*4;for(int i=0;i<4;i++){s[4*i]^=(rk[b+i]>>24)&0xff;s[4*i+1]^=(rk[b+i]>>16)&0xff;s[4*i+2]^=(rk[b+i]>>8)&0xff;s[4*i+3]^=rk[b+i]&0xff;}
    }
    memcpy(out,s,16);
}
static void _aes_ctr(u8*buf,size_t len,const u8 key[16],const u8 nonce[16]){
    u32 rk[44];_kx(key,rk);
    u8 ctr[16],ks[16];memcpy(ctr,nonce,16);
    size_t i=0;
    while(i<len){_enc(ctr,ks,rk);for(int j=12;j<16;j++)if(++ctr[j])break;size_t n=len-i<16?len-i:16;for(size_t k2=0;k2<n;k2++)buf[i+k2]^=ks[k2];i+=16;}
    _zero(rk,sizeof(rk));
}

/* ── Anti-debug ──────────────────────────────────────────────────────── */
static int _adbg(void){
    if(ptrace(PTRACE_TRACEME,0,0,0)<0)return 1;
    ptrace(PTRACE_DETACH,0,0,0);
    FILE *f=fopen("/proc/self/status","r");
    if(f){char ln[128];while(fgets(ln,sizeof(ln),f)){if(strncmp(ln,"TracerPid:",10)==0){int pid=atoi(ln+10);fclose(f);if(pid)return 1;break;}}fclose(f);}
    struct timespec t0,t1;clock_gettime(CLOCK_MONOTONIC,&t0);volatile long x=0;for(int i=0;i<50000;i++)x^=i;clock_gettime(CLOCK_MONOTONIC,&t1);
    if((t1.tv_sec-t0.tv_sec)*1000000000L+(t1.tv_nsec-t0.tv_nsec)>100000000L)return 1;
    return 0;
}

/* ── Decrypt common path ─────────────────────────────────────────────── */
static u8 *_decrypt(const u8*enc,Py_ssize_t enc_len,
                    PyObject*frags,int step,
                    PyObject*inv_perm,Py_ssize_t orig_len,
                    const u8 nonce[16])
{
    /* AES-CTR */
    u8 key[16];_get_key(key);
    u8 *ab=(u8*)malloc((size_t)enc_len);
    if(!ab){_zero(key,16);return NULL;}
    memcpy(ab,enc,enc_len);
    _aes_ctr(ab,(size_t)enc_len,key,nonce);
    _zero(key,16);

    /* Reconstruct XOR key from N fragments */
    Py_ssize_t nf=PyList_Size(frags);
    Py_ssize_t kl=PyList_Size(PyList_GET_ITEM(frags,0));
    u8 *ka=(u8*)calloc((size_t)kl,1);
    if(!ka){free(ab);return NULL;}
    for(Py_ssize_t f=0;f<nf;f++){
        PyObject*fr=PyList_GET_ITEM(frags,f);
        Py_ssize_t fl=PyList_Size(fr);
        for(Py_ssize_t j=0;j<fl&&j<kl;j++) ka[j]^=(u8)(PyLong_AsLong(PyList_GET_ITEM(fr,j))&0xFF);
    }

    /* Undo permutation */
    Py_ssize_t pl=PyList_Size(inv_perm);
    Py_ssize_t bl=pl<enc_len?pl:enc_len;
    u8 *d2=(u8*)malloc((size_t)bl);
    if(!d2){_zero(ka,(size_t)kl);free(ka);free(ab);return NULL;}
    for(Py_ssize_t i=0;i<bl;i++){
        Py_ssize_t p=PyLong_AsSsize_t(PyList_GET_ITEM(inv_perm,i));
        d2[i]=(p>=0&&p<enc_len)?ab[p]:0;
    }
    free(ab);

    /* Undo rolling XOR */
    u8 *d1=(u8*)malloc((size_t)orig_len);
    if(!d1){_zero(ka,(size_t)kl);free(ka);free(d2);return NULL;}
    int ki=0;
    for(Py_ssize_t i=0;i<orig_len;i++){
        d1[i]=(i<bl?d2[i]:0)^ka[ki];
        ki=(ki+step)%(int)kl;
    }
    _zero(ka,(size_t)kl);free(ka);free(d2);
    return d1;
}

/* ── Pyrph C VM ──────────────────────────────────────────────────────── */
/* Opcode IDs — must match ALL_OPCODES order in vm/opcodes.py */
enum _op {
    OP_LOAD_CONST=0,OP_LOAD_NAME,OP_STORE_NAME,OP_DEL_NAME,
    OP_POP,OP_DUP,OP_ROT2,OP_ROT3,
    OP_REG_LOAD,OP_REG_STORE,OP_REG_LOADK,OP_REG_MOV,
    OP_ADD,OP_SUB,OP_MUL,OP_DIV,OP_FLOORDIV,OP_MOD,OP_POW,OP_NEG,OP_POS,
    OP_BAND,OP_BOR,OP_BXOR,OP_BINV,OP_BSHL,OP_BSHR,
    OP_CMP_EQ,OP_CMP_NE,OP_CMP_LT,OP_CMP_LE,OP_CMP_GT,OP_CMP_GE,
    OP_CMP_IN,OP_CMP_NOT_IN,OP_CMP_IS,OP_CMP_IS_NOT,OP_NOT,
    OP_JMP,OP_JMP_TRUE,OP_JMP_FALSE,OP_JMP_TRUE_PEEK,OP_JMP_FALSE_PEEK,
    OP_MAKE_FUNC,OP_CALL,OP_CALL_KW,OP_CALL_METHOD,OP_RETURN,
    OP_GET_ATTR,OP_SET_ATTR,OP_DEL_ATTR,
    OP_GET_ITEM,OP_SET_ITEM,OP_DEL_ITEM,OP_SLICE,
    OP_BUILD_LIST,OP_BUILD_TUPLE,OP_BUILD_DICT,OP_BUILD_SET,OP_BUILD_STR,
    OP_GET_ITER,OP_FOR_ITER,OP_UNPACK,
    OP_IMPORT,OP_IMPORT_FROM,
    OP_SETUP_TRY,OP_POP_TRY,OP_RAISE,
    OP_FORMAT_VAL,OP_HALT,
};

#define STKSZ 4096
#define REGS  8

static PyObject* _vm_run(
    const u8*bc, Py_ssize_t bc_len,
    const u8*opmap,
    PyObject*consts, PyObject*names, PyObject*globs, PyObject*arg_map)
{
    PyObject**stk=(PyObject**)calloc(STKSZ,sizeof(PyObject*));
    if(!stk){PyErr_NoMemory();return NULL;}
    int sp=0;
    PyObject*regs[REGS]={NULL};
    PyObject*frame=PyDict_New();
    if(!frame){free(stk);PyErr_NoMemory();return NULL;}
    if(arg_map) PyDict_Merge(frame,arg_map,0);

    PyObject*result=Py_None; Py_INCREF(result);
    Py_ssize_t ip=0;

#define NEXT() (ip<bc_len?(int)(u8)bc[ip++]:-1)
#define U16()  (ip+1<bc_len?((int)((u8)bc[ip]<<8|(u8)bc[ip+1]))+(ip+=2)*0:(ip+=2,-1))
#define OP(r)  ((int)opmap[(u8)(r)])
#define PUSH(v) do{if(sp>=STKSZ){PyErr_SetString(PyExc_RuntimeError,"vm stack overflow");goto _err;}stk[sp++]=(v);}while(0)
#define POP()  (sp>0?stk[--sp]:(PyErr_SetString(PyExc_RuntimeError,"vm underflow"),NULL))
#define PEEK() (sp>0?stk[sp-1]:(PyErr_SetString(PyExc_RuntimeError,"vm empty"),NULL))
#define CHKERR() if(PyErr_Occurred()) goto _err

    while(ip<bc_len){
        int raw=NEXT(); if(raw<0)break;
        int op=OP(raw);
        switch(op){

        case OP_LOAD_CONST:{int a=NEXT();PyObject*v=PyList_GET_ITEM(consts,a);Py_INCREF(v);PUSH(v);break;}
        case OP_LOAD_NAME:{int a=NEXT();PyObject*k=PyList_GET_ITEM(names,a);PyObject*v=PyDict_GetItem(frame,k);if(!v)v=PyDict_GetItem(globs,k);if(!v){v=PyObject_GetAttr(PyEval_GetBuiltins(),k);}else Py_INCREF(v);if(!v){PyErr_Format(PyExc_NameError,"name '%S' not defined",k);goto _err;}PUSH(v);break;}
        case OP_STORE_NAME:{int a=NEXT();PyObject*v=POP();if(!v){CHKERR();break;}PyDict_SetItem(frame,PyList_GET_ITEM(names,a),v);Py_DECREF(v);break;}
        case OP_DEL_NAME:{int a=NEXT();PyDict_DelItem(frame,PyList_GET_ITEM(names,a));PyErr_Clear();break;}
        case OP_POP:{PyObject*v=POP();Py_XDECREF(v);break;}
        case OP_DUP:{PyObject*v=PEEK();if(!v){CHKERR();break;}Py_INCREF(v);PUSH(v);break;}
        case OP_ROT2:{if(sp>=2){PyObject*t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=t;}break;}
        case OP_ROT3:{if(sp>=3){PyObject*t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=stk[sp-3];stk[sp-3]=t;}break;}
        case OP_REG_LOAD:{int a=NEXT()&7;PyObject*v=regs[a]?regs[a]:Py_None;Py_INCREF(v);PUSH(v);break;}
        case OP_REG_STORE:{int a=NEXT()&7;PyObject*v=POP();if(!v){CHKERR();break;}Py_XDECREF(regs[a]);regs[a]=v;break;}

#define BINOP(fn) {PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}PyObject*r=(fn)(a,b);Py_DECREF(a);Py_DECREF(b);if(!r){CHKERR();break;}PUSH(r);}
        case OP_ADD: BINOP(PyNumber_Add);       break;
        case OP_SUB: BINOP(PyNumber_Subtract);  break;
        case OP_MUL: BINOP(PyNumber_Multiply);  break;
        case OP_DIV: BINOP(PyNumber_TrueDivide);break;
        case OP_FLOORDIV: BINOP(PyNumber_FloorDivide);break;
        case OP_MOD: BINOP(PyNumber_Remainder); break;
        case OP_BAND: BINOP(PyNumber_And);      break;
        case OP_BOR:  BINOP(PyNumber_Or);       break;
        case OP_BXOR: BINOP(PyNumber_Xor);      break;
        case OP_BSHL: BINOP(PyNumber_Lshift);   break;
        case OP_BSHR: BINOP(PyNumber_Rshift);   break;
        case OP_POW:{PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}PyObject*r=PyNumber_Power(a,b,Py_None);Py_DECREF(a);Py_DECREF(b);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_NEG:{PyObject*a=POP();if(!a){CHKERR();break;}PyObject*r=PyNumber_Negative(a);Py_DECREF(a);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_POS:{PyObject*a=POP();if(!a){CHKERR();break;}PyObject*r=PyNumber_Positive(a);Py_DECREF(a);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_BINV:{PyObject*a=POP();if(!a){CHKERR();break;}PyObject*r=PyNumber_Invert(a);Py_DECREF(a);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_NOT:{PyObject*a=POP();if(!a){CHKERR();break;}int t=PyObject_IsTrue(a);Py_DECREF(a);if(t<0){CHKERR();break;}PyObject*r=t?Py_False:Py_True;Py_INCREF(r);PUSH(r);break;}

#define CMP(op2) {PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}PyObject*r=PyObject_RichCompare(a,b,(op2));Py_DECREF(a);Py_DECREF(b);if(!r){CHKERR();break;}PUSH(r);}
        case OP_CMP_EQ: CMP(Py_EQ);break;
        case OP_CMP_NE: CMP(Py_NE);break;
        case OP_CMP_LT: CMP(Py_LT);break;
        case OP_CMP_LE: CMP(Py_LE);break;
        case OP_CMP_GT: CMP(Py_GT);break;
        case OP_CMP_GE: CMP(Py_GE);break;
        case OP_CMP_IS:{PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}PyObject*r=a==b?Py_True:Py_False;Py_DECREF(a);Py_DECREF(b);Py_INCREF(r);PUSH(r);break;}
        case OP_CMP_IS_NOT:{PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}PyObject*r=a!=b?Py_True:Py_False;Py_DECREF(a);Py_DECREF(b);Py_INCREF(r);PUSH(r);break;}
        case OP_CMP_IN:{PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}int r=PySequence_Contains(b,a);Py_DECREF(a);Py_DECREF(b);if(r<0){CHKERR();break;}PyObject*rv=r?Py_True:Py_False;Py_INCREF(rv);PUSH(rv);break;}
        case OP_CMP_NOT_IN:{PyObject*b=POP(),*a=POP();if(!a||!b){Py_XDECREF(a);Py_XDECREF(b);CHKERR();break;}int r=PySequence_Contains(b,a);Py_DECREF(a);Py_DECREF(b);if(r<0){CHKERR();break;}PyObject*rv=r?Py_False:Py_True;Py_INCREF(rv);PUSH(rv);break;}

        case OP_JMP:{int t=U16();ip=t;break;}
        case OP_JMP_TRUE:{int t=U16();PyObject*v=POP();if(!v){CHKERR();break;}int b=PyObject_IsTrue(v);Py_DECREF(v);if(b<0){CHKERR();break;}if(b)ip=t;break;}
        case OP_JMP_FALSE:{int t=U16();PyObject*v=POP();if(!v){CHKERR();break;}int b=PyObject_IsTrue(v);Py_DECREF(v);if(b<0){CHKERR();break;}if(!b)ip=t;break;}
        case OP_JMP_TRUE_PEEK:{int t=U16();if(sp>0){int b=PyObject_IsTrue(stk[sp-1]);if(b>0)ip=t;}break;}
        case OP_JMP_FALSE_PEEK:{int t=U16();if(sp>0){int b=PyObject_IsTrue(stk[sp-1]);if(b==0)ip=t;}break;}

        case OP_CALL:{int argc=NEXT();PyObject*tup=PyTuple_New(argc);for(int i=argc-1;i>=0;i--){PyObject*v=POP();if(!v){Py_DECREF(tup);CHKERR();goto _err;}PyTuple_SET_ITEM(tup,i,v);}PyObject*fn=POP();if(!fn){Py_DECREF(tup);CHKERR();break;}PyObject*r=PyObject_Call(fn,tup,NULL);Py_DECREF(fn);Py_DECREF(tup);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_GET_ATTR:{int a=NEXT();PyObject*o=POP();if(!o){CHKERR();break;}PyObject*r=PyObject_GetAttr(o,PyList_GET_ITEM(names,a));Py_DECREF(o);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_SET_ATTR:{int a=NEXT();PyObject*v=POP(),*o=POP();if(!o||!v){Py_XDECREF(o);Py_XDECREF(v);CHKERR();break;}PyObject_SetAttr(o,PyList_GET_ITEM(names,a),v);Py_DECREF(o);Py_DECREF(v);CHKERR();break;}
        case OP_GET_ITEM:{PyObject*k=POP(),*o=POP();if(!o||!k){Py_XDECREF(o);Py_XDECREF(k);CHKERR();break;}PyObject*r=PyObject_GetItem(o,k);Py_DECREF(o);Py_DECREF(k);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_SET_ITEM:{PyObject*v=POP(),*k=POP(),*o=POP();if(!o||!k||!v){Py_XDECREF(o);Py_XDECREF(k);Py_XDECREF(v);CHKERR();break;}PyObject_SetItem(o,k,v);Py_DECREF(o);Py_DECREF(k);Py_DECREF(v);CHKERR();break;}
        case OP_BUILD_LIST:{int n=NEXT();PyObject*ls=PyList_New(n);for(int i=n-1;i>=0;i--){PyObject*v=POP();PyList_SET_ITEM(ls,i,v?v:Py_None);}PUSH(ls);break;}
        case OP_BUILD_TUPLE:{int n=NEXT();PyObject*t=PyTuple_New(n);for(int i=n-1;i>=0;i--){PyObject*v=POP();PyTuple_SET_ITEM(t,i,v?v:Py_None);}PUSH(t);break;}
        case OP_BUILD_DICT:{int n=NEXT();PyObject*d=PyDict_New();for(int i=0;i<n;i++){PyObject*v=POP(),*k=POP();if(k&&v)PyDict_SetItem(d,k,v);Py_XDECREF(k);Py_XDECREF(v);}PUSH(d);break;}
        case OP_GET_ITER:{if(sp>0){PyObject*o=POP();PyObject*it=PyObject_GetIter(o);Py_DECREF(o);if(!it){CHKERR();break;}PUSH(it);}break;}
        case OP_FOR_ITER:{int t=U16();if(sp==0)break;PyObject*it=stk[sp-1];PyObject*v=(*Py_TYPE(it)->tp_iternext)(it);if(v){PUSH(v);}else{if(PyErr_ExceptionMatches(PyExc_StopIteration))PyErr_Clear();Py_DECREF(POP());ip=t;}break;}
        case OP_UNPACK:{int n=NEXT();PyObject*seq=POP();if(!seq){CHKERR();break;}PyObject*ls=PySequence_List(seq);Py_DECREF(seq);if(!ls){CHKERR();break;}for(int i=n-1;i>=0;i--){PyObject*v=PyList_GET_ITEM(ls,i);Py_INCREF(v);PUSH(v);}Py_DECREF(ls);break;}
        case OP_IMPORT:{int a=NEXT();PyObject*r=PyImport_Import(PyList_GET_ITEM(names,a));if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_RETURN:{PyObject*v=POP();Py_DECREF(result);result=v?v:Py_None;if(!v)Py_INCREF(result);ip=bc_len;break;}
        case OP_RAISE:{PyObject*e=POP();if(e&&e!=Py_None){PyErr_SetObject((PyObject*)Py_TYPE(e),e);Py_DECREF(e);}else{if(!PyErr_Occurred())PyErr_SetString(PyExc_RuntimeError,"raise");Py_XDECREF(e);}goto _err;}
        case OP_FORMAT_VAL:{PyObject*a=POP();if(!a){CHKERR();break;}PyObject*r=PyObject_Str(a);Py_DECREF(a);if(!r){CHKERR();break;}PUSH(r);break;}
        case OP_HALT: ip=bc_len; break;
        default: break;
        }
    }

    if(!arg_map){PyObject*k,*v;Py_ssize_t pos=0;while(PyDict_Next(frame,&pos,&k,&v))PyDict_SetItem(globs,k,v);}
    while(sp>0){Py_XDECREF(stk[--sp]);}
    for(int i=0;i<REGS;i++){Py_XDECREF(regs[i]);}
    Py_DECREF(frame);free(stk);
    return result;
_err:
    while(sp>0){Py_XDECREF(stk[--sp]);}
    for(int i=0;i<REGS;i++){Py_XDECREF(regs[i]);}
    Py_DECREF(frame);Py_DECREF(result);free(stk);
    return NULL;
}

/* ── Python-exposed functions ────────────────────────────────────────── */

static PyObject* _py_decrypt_exec(PyObject*self,PyObject*args){
    Py_buffer ev,nv;PyObject*frags;int step;PyObject*ip;Py_ssize_t olen;const char*ff;PyObject*globs;
    if(!PyArg_ParseTuple(args,"y*OiOny*zO",&ev,&frags,&step,&ip,&olen,&nv,&ff,&globs))return NULL;
    if(_adbg()){PyBuffer_Release(&ev);PyBuffer_Release(&nv);PyErr_SetString(PyExc_ImportError,"cannot import name '_bootstrap' from 'importlib'");return NULL;}
    u8 nonce[16];memcpy(nonce,nv.buf,16);PyBuffer_Release(&nv);
    u8*d=_decrypt((const u8*)ev.buf,ev.len,frags,step,ip,olen,nonce);PyBuffer_Release(&ev);
    if(!d)return NULL;
    PyObject*cb=PyBytes_FromStringAndSize((char*)d,olen);_zero(d,(size_t)olen);free(d);
    if(!cb)return NULL;
    PyObject*co=PyMarshal_ReadObjectFromString(PyBytes_AS_STRING(cb),PyBytes_GET_SIZE(cb));Py_DECREF(cb);
    if(!co)return NULL;
    if(!PyCode_Check(co)){Py_DECREF(co);PyErr_SetString(PyExc_TypeError,"bad code");return NULL;}
    if(!PyDict_GetItemString(globs,"__builtins__"))PyDict_SetItemString(globs,"__builtins__",PyEval_GetBuiltins());
    if(ff){PyObject*ffo=PyUnicode_FromString(ff);PyDict_SetItemString(globs,"__file__",ffo);Py_DECREF(ffo);}
    PyObject*res=PyEval_EvalCode(co,globs,globs);
    PyObject*co_bytes=PyCode_GetCode((PyCodeObject*)co);
    if(co_bytes){_zero(PyBytes_AS_STRING(co_bytes),(size_t)PyBytes_GET_SIZE(co_bytes));Py_DECREF(co_bytes);}
    Py_DECREF(co);
    return res;
}

static PyObject* _py_decrypt_exec_vm(PyObject*self,PyObject*args){
    Py_buffer ev,nv,omv;PyObject*frags;int step;PyObject*ip;Py_ssize_t olen;PyObject*consts,*names,*globs;const char*ff;
    if(!PyArg_ParseTuple(args,"y*OiOny*y*OOzO",&ev,&frags,&step,&ip,&olen,&nv,&omv,&consts,&names,&ff,&globs))return NULL;
    if(_adbg()){PyBuffer_Release(&ev);PyBuffer_Release(&nv);PyBuffer_Release(&omv);PyErr_SetString(PyExc_ImportError,"cannot import name '_bootstrap' from 'importlib'");return NULL;}
    if(omv.len<256){PyBuffer_Release(&ev);PyBuffer_Release(&nv);PyBuffer_Release(&omv);PyErr_SetString(PyExc_ValueError,"opmap must be 256 bytes");return NULL;}
    const u8*omap=(const u8*)omv.buf;
    u8 nonce[16];memcpy(nonce,nv.buf,16);PyBuffer_Release(&nv);
    u8*d=_decrypt((const u8*)ev.buf,ev.len,frags,step,ip,olen,nonce);
    PyBuffer_Release(&ev);PyBuffer_Release(&omv);
    if(!d)return NULL;
    if(!PyDict_GetItemString(globs,"__builtins__"))PyDict_SetItemString(globs,"__builtins__",PyEval_GetBuiltins());
    if(ff){PyObject*ffo=PyUnicode_FromString(ff);PyDict_SetItemString(globs,"__file__",ffo);Py_DECREF(ffo);}
    PyObject*res=_vm_run(d,olen,omap,consts,names,globs,NULL);
    _zero(d,(size_t)olen);free(d);
    return res;
}

static PyObject* _py_version(PyObject*s,PyObject*a){return PyLong_FromLong(0x50595246);}

#pragma GCC visibility pop

static PyMethodDef _methods[]={
    {"decrypt_exec",    _py_decrypt_exec,    METH_VARARGS,NULL},
    {"decrypt_exec_vm", _py_decrypt_exec_vm, METH_VARARGS,NULL},
    {"version",         _py_version,         METH_NOARGS, NULL},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef _mod={PyModuleDef_HEAD_INIT,"_pyrph",NULL,-1,_methods};
PyMODINIT_FUNC PyInit__pyrph(void){return PyModule_Create(&_mod);}
