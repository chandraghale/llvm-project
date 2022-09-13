void test_1(){
        char x = -1; // expected-warning {{assigning negative value to a plain char variable loses sign and may cause undesired runtime behavior}}
        unsigned char y = -10; // no-warning
        int z = -1; // no-warning
        unsigned int p = -10; // no-warning
        char q = 10; // no-warning
}

void test_2(){
        int x = -10; // no-warning
        char y = x; // expected-warning {{assigning negative value to a plain char variable loses sign and may cause undesired runtime behavior}}
}

void test_3(int x){
        char z = x; // expected-warning {{assigning negative value to a plain char variable loses sign and may cause undesired runtime behavior}}
}

void test_3.1(){
        int z = -9;
        test_3(z);
}
