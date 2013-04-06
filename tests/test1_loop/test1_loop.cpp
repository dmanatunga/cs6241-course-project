
int main(int argc, char ** argv) {
  int arr[argc];
  arr[argc] = argc;
  for (int i = 0; i < argc; i++) {
    int x = 2;
    int a = argc + x;
    arr[i] =a;
  }
  int x = arr[argc];
  return x; 
}


