#include "syscalls/syscalls.h"
#include "math/math.h"
#include "memory.h"

typedef struct {
    u16 digits;
    u16 size;
    u16 num[];
} bigint;

bigint *bigint_create(int digits){
    bigint *b = zalloc((digits * sizeof(u16)) + 4);
    b->size = digits + 4;
    return b;
}

void bigint_multiply(bigint *n, bigint *m){
    u16 mc = m->digits;
    u16 nc = n->digits;
    
    bigint *buf = bigint_create(mc+nc);
    
    for (int i = 0; i < m->digits; i++){
        for (int j = 0; j < n->digits; j++){
            u16 md = m->num[i];
            u16 nd = n->num[j];
            buf->num[i+j] += md * nd;
        }
    }
    u16 carry = 0;
    memset(n->num, 0, nc*sizeof(u16));
    n->digits = 0;
    for (int i = 0; i < mc+nc; i++){
        buf->num[i] += carry % 10;
        carry /= 10;
        i8 digit = buf->num[i] % 10;
        carry += buf->num[i] / 10;
        n->num[i] = digit;
        n->digits++;
    }
    int dc;
    for (dc = n->digits-1; dc >= 0; dc--){
        if (n->num[dc] != 0)
            break;
    }
    release(buf);
    n->digits = dc+1;
}

int bigint_compare(bigint *a, bigint *b){
    if (a->digits < b->digits) return -1;
    if (a->digits > b->digits) return 1;
    int n = a->digits;
    while(n--){
        if (a->num[n] != b->num[n]){
            if (a->num[n] < b->num[n]) return -1;
            if (a->num[n] > b->num[n]) return 1;
        }
    }
    return 0;
}

void bigint_append_digit(bigint *b, int amount){
    //TODO: overflow check
    for (int i = b->digits-1; i >= 0; i--){
        b->num[i+1] = b->num[i];
    }
    b->num[0] = amount;
    b->digits++;
}

void bigint_sub(bigint *a, bigint *b){
    if (bigint_compare(a,b) < 0)
        return;
    int n = a->digits;
    int m = b->digits;
    int borrow = 0;
    for (int i = 0; i < n; i++){
        int result = 0;
        if (i < m)
            result = a->num[i] - b->num[i] - borrow;
        else result = a->num[i] - borrow;
        if (result < 0){
           result += 10;
           borrow = 1;
        } else borrow = 0;
        a->num[i] = result;
    }
    int dc;
    for (dc = a->digits-1; dc >= 0; dc--){
        if (a->num[dc] != 0)
            break;
    }
    a->digits = dc+1;
}

void bigint_modulo(bigint *n, bigint *d){
    if (n->digits == 0) return;
    if (bigint_compare(n,d) < 0) return;
    if (bigint_compare(n,d) == 0) {
        memset(n->num, 0, n->digits*sizeof(u16));
        n->digits = 0;
        return;
    }
    
    int i = n->digits;
    int compare;
    
    bigint *buffer = bigint_create(n->digits);
    do {
        i--;
        bigint_append_digit(buffer,n->num[i]);
        compare = bigint_compare(buffer, d);
    } while (compare < 0);
    
    bigint *mulbuf = bigint_create(d->digits+1);
    bigint *cc = bigint_create(1);
    
    while (i >= 0){
        for (int c = 9; c > 0; c--){
            cc->num[0] = c;
            cc->digits = 1;
            memcpy(mulbuf->num, d->num, d->digits*sizeof(u16));
            mulbuf->digits = d->digits;
            bigint_multiply(mulbuf, cc);
            
            if (bigint_compare(mulbuf, buffer) <= 0){
                bigint_sub(buffer,mulbuf);
                break;
            }
        }
        
        i--;
        if (i >= 0){
            bigint_append_digit(buffer,n->num[i]);
        }
    }
    
    memcpy(n->num, buffer->num, buffer->digits*sizeof(u16));
    n->digits = buffer->digits;
    release(mulbuf);
    release(cc);
    release(buffer);
}

bigint *u64_to_bigint(u64 n){
    bigint *b = bigint_create(30);
    while (n){
        int digit = n % 10;
        b->num[b->digits++] = digit;
        n /= 10;
    }
    return b;
}

bigint* bigint_pow_mod(bigint *bin, u64 e, bigint *mod){
    bigint *result = bigint_create(2000);
    memcpy(result->num, bin->num, bin->digits*sizeof(u16));
    result->digits = bin->digits;
    for (i64 i = 1; i < e; i++){
        bigint_multiply(result, bin);
        bigint_modulo(result, mod);
    }
    return result;
}

void rsa_demo(){
    i64 p = 61;//Private TODO: calculate
    i64 q = 53;//Private TODO: calculate
    
    i64 n = p*q;//3233
    
    print("N: %li",n);
    
    i64 ln = 780;//TODO: lcm(p,q);
    
    i64 e = 17;//TODO: 1 < e < ln where ln and e are coprime
    
    print("E: %li",e);
    
    i64 d = 413;//TODO: e^-1 % ln
    
    i64 m = 65;
    
    bigint *bigm = u64_to_bigint(m);
    
    bigint *bign = u64_to_bigint(n);
    bigint *c = bigint_pow_mod(bigm, e, bign);
    
    for (int i = 0; i < c->digits; i++){
        print("Encrypted %i = %i",i,c->num[i]);
    }
    
    print("================");
    
    c = bigint_pow_mod(c, d, bign);
    
    for (int i = 0; i < c->digits; i++){
        print("Decrypted %i = %i",i,c->num[i]);
    }
}

void dh_demo(){
    
    bigint *p = u64_to_bigint(23);//public
    bigint *g = u64_to_bigint(5);//public
    
    i64 a = 4;//private
    i64 b = 3;//private
    
    bigint *A = bigint_pow_mod(g, a, p);
    
    print("Alice's public key: ");
    for (int i = 0; i < A->digits; i++){
        print("Decrypted %i = %i",i,A->num[i]);
    }
    
    bigint *B = bigint_pow_mod(g, b, p);
    
    print("Bob's public key: ");
    for (int i = 0; i < B->digits; i++){
        print("Decrypted %i = %i",i,B->num[i]);
    }
    
    bigint *sh1 = bigint_pow_mod(A, b, p);
    bigint *sh2 = bigint_pow_mod(B, a, p);
    
    bool match = true;
    for (int i = 0; i < sh1->digits && i < sh2->digits; i++){
        match &= sh1->num[i] == sh2->num[i];
        if (!match){
            print("Error: Shared key does not match on digit %i = %i vs %i",i,sh1->num[i],sh2->num[i]);
            return;
        } else print("%i. %i == %i",i,sh1->num[i],sh2->num[i]);
    }
    
    if (match)
        print("Shared secret match");
    
}

int main(int argc, char *argv[]){
    print("Hallo, wereld!");
    
    dh_demo();
    
    return 0;
}