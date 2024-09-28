rm -f *.o
rm -f *exe
rm -f acllib/*.o
rm -f BitOp/*.o
rm -f gluethread/*.o
rm -f mtrie/*.o
rm -f stack/*.o
rm -f *.a


g++ -g -c acllib/acl_lib_util.c -o acllib/acl_lib_util.o 
g++ -g -c acllib/acl_lib.c -o acllib/acl_lib.o

g++ -g -c BitOp/bitmap.c -o BitOp/bitmap.o

g++ -g -c gluethread/glthread.c -o gluethread/glthread.o

g++ -g -c stack/stack.c -o stack/stack.o
g++ -g -c mtrie/mtrie.c -o mtrie/mtrie.o 

g++ -g -c acl_ui.c -o acl_ui.o
g++ -g -c rt_ui.c -o rt_ui.o

ar rs libacl.a acllib/acl_lib_util.o \
                     acllib/acl_lib.o \
                     BitOp/bitmap.o \
                     gluethread/glthread.o \
                     mtrie/mtrie.o \
                     acl_ui.o \
                     rt_ui.o
