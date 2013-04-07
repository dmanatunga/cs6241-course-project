
int main(int argc, char ** argv) {
  int arr[5] = {1, 2,3, 4, 5};
  int x = argc;
  int j = 0;
  for (int i = 0; i < argc; i++) {
    j += arr[x];
  }
  return 0; 
}


