#include<stdlib.h>
#include<stdio.h>
char *srcGrid;
void start(char **ptr){
 // first escape
 *ptr = malloc(0x64b54000);

  // second escape
  // generate a false escape
 *ptr += 0x186a00;

}

void end(char **ptr){
 free(*ptr - 0x186a00);
}
int main(){
 
 start(  &srcGrid  );
 end( &srcGrid   );
 return 0;
}