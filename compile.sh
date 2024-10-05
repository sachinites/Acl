rm -f *.o
rm -f *exe
rm -f acllib/*.o
rm -f BitOp/*.o
rm -f gluethread/*.o
rm -f mtrie/*.o
rm -f stack/*.o
rm -f *.a

CFLAGS=-g -fpermissive -Wdeprecated

g++ ${CFLAGS} -c acllib/acl_lib_util.c -o acllib/acl_lib_util.o 
g++ ${CFLAGS} -c acllib/acl_lib.c -o acllib/acl_lib.o
g++ ${CFLAGS} -c acllib/acl_parser.c -o acllib/acl_parser.o
cd acllib
lex Parser.l
cd .. 
g++ ${CFLAGS} -c acllib/lex.yy.c -o acllib/lex.yy.o -fpermissive

g++ ${CFLAGS} -c BitOp/bitmap.c -o BitOp/bitmap.o

g++ ${CFLAGS} -c gluethread/glthread.c -o gluethread/glthread.o

g++ ${CFLAGS} -c stack/stack.c -o stack/stack.o
g++ ${CFLAGS} -c mtrie/mtrie.c -o mtrie/mtrie.o 

g++ ${CFLAGS} -c acl_ui.c -o acl_ui.o
g++ ${CFLAGS} -c rt_ui.c -o rt_ui.o

ar rs libacl.a acllib/acl_lib_util.o \
                     acllib/acl_lib.o \
                     acllib/acl_parser.o \
                     acllib/lex.yy.o \
                     BitOp/bitmap.o \
                     gluethread/glthread.o \
                     mtrie/mtrie.o \
                     acl_ui.o \
                     rt_ui.o
