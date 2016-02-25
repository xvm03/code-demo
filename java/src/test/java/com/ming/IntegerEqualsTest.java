package com.ming;

import junit.framework.TestCase;

/**
 * xumingming 16/2/25.
 */
public class IntegerEqualsTest extends TestCase {


    IntegerEquals integerEquals = new IntegerEquals();

    //默认情况下-128到127之间，会缓存
    public void testLt(){
        assertTrue(integerEquals.lessThan128());
    }

    //
    public void testGt(){
        assertFalse(integerEquals.greateThan128());
    }
}
