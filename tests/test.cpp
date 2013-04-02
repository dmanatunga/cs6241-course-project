
int count = 0;

int main(int argc, char ** argv) {
  int arr[5] = {1, 2, 3, 4, 5};

  
  int i = -1 + 2;
  int j = arr[i];
  int *p = &j;
  count = count + 1;
  *p = -1;
  count = count + 2;
  i = -2 + i + 1;
  int k = arr[i+1];
  int l = arr[2];
  return 0;
}
