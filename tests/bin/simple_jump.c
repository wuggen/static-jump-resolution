// gcc -static -no-pie -c simple_jump.c
// Compiled with gcc 9.2.0

int foo(char *msg) {
  return msg[0];
}

int bar(char *msg) {
  return msg[0] + 10;
}

int main(int argc, char **argv) {
  int (*fn)(char*);

  if (argc == 1) {
    fn = foo;
  } else {
    fn = bar;
  }

  return fn(argv[0]);
}
