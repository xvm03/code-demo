package com.ming;

/**
 *
 * java的常量池之integer缓存
 * xumingming 16/2/25.
 */
public class IntegerEquals {


    //[-128,127]之间常量池缓存,"=="会自动装箱，调用valueOf，valueOf会从缓存池里直接拿
    boolean lessThan128(){

        Integer a = 127;
        Integer b = 127;

        return a==b;

    }

    //(127,)直接比较的是对象引用，可以通过Jvm参数 -XX:AutoBoxCacheMax=size 增大该值

    boolean greateThan128(){

        Integer a = 128;
        Integer b = 128;
        return a==b;

    }


}
