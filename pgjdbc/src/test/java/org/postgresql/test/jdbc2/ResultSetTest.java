/*
 * Copyright (c) 2004, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test.jdbc2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.postgresql.PGConnection;
import org.postgresql.core.ServerVersion;
import org.postgresql.jdbc.PreferQueryMode;
import org.postgresql.test.TestUtil;
import org.postgresql.util.PGobject;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * ResultSet tests.
 */
@ParameterizedClass
@MethodSource("data")
public class ResultSetTest extends BaseTest4 {

  public ResultSetTest(BinaryMode binaryMode) {
    setBinaryMode(binaryMode);
  }

  public static Iterable<Object[]> data() {
    Collection<Object[]> ids = new ArrayList<>();
    for (BinaryMode binaryMode : BinaryMode.values()) {
      ids.add(new Object[]{binaryMode});
    }
    return ids;
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    Statement stmt = con.createStatement();

    TestUtil.createTable(con, "testrs", "id integer");

    stmt.executeUpdate("INSERT INTO testrs VALUES (1)");
    stmt.executeUpdate("INSERT INTO testrs VALUES (2)");
    stmt.executeUpdate("INSERT INTO testrs VALUES (3)");
    stmt.executeUpdate("INSERT INTO testrs VALUES (4)");
    stmt.executeUpdate("INSERT INTO testrs VALUES (6)");
    stmt.executeUpdate("INSERT INTO testrs VALUES (9)");

    TestUtil.createTable(con, "teststring", "a text");
    stmt.executeUpdate("INSERT INTO teststring VALUES ('12345')");

    TestUtil.createTable(con, "testint", "a int");
    stmt.executeUpdate("INSERT INTO testint VALUES (12345)");

    // Boolean Tests
    TestUtil.createTable(con, "testbool", "a boolean, b int");
    stmt.executeUpdate("INSERT INTO testbool VALUES(true, 1)");
    stmt.executeUpdate("INSERT INTO testbool VALUES(false, 0)");

    TestUtil.createTable(con, "testboolstring", "a varchar(30), b boolean");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('1 ', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('0', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES(' t', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('f', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('True', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('      False   ', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('yes', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('  no  ', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('y', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('n', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('oN', true)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('oFf', false)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('OK', null)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('NOT', null)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('not a boolean', null)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('1.0', null)");
    stmt.executeUpdate("INSERT INTO testboolstring VALUES('0.0', null)");

    TestUtil.createTable(con, "testboolfloat", "i int, a float4, b boolean");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(1, '1.0'::real, true)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(2, '0.0'::real, false)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(3, 1.000::real, true)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(4, 0.000::real, false)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(5, '1.001'::real, null)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(6, '-1.001'::real, null)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(7, 123.4::real, null)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(8, 1.234e2::real, null)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(9, 100.00e-2::real, true)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(10, '9223371487098961921', null)");
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(11, '10223372036850000000', null)");
    String floatVal = Float.toString(StrictMath.nextDown(Long.MAX_VALUE - 1));
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(12, " + floatVal + ", null)");
    floatVal = Float.toString(StrictMath.nextDown(Long.MAX_VALUE + 1));
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(13, " + floatVal + ", null)");
    floatVal = Float.toString(StrictMath.nextUp(Long.MIN_VALUE - 1));
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(14, " + floatVal + ", null)");
    floatVal = Float.toString(StrictMath.nextUp(Long.MIN_VALUE + 1));
    stmt.executeUpdate("INSERT INTO testboolfloat VALUES(15, " + floatVal + ", null)");

    TestUtil.createTable(con, "testboolint", "a bigint, b boolean");
    stmt.executeUpdate("INSERT INTO testboolint VALUES(1, true)");
    stmt.executeUpdate("INSERT INTO testboolint VALUES(0, false)");
    stmt.executeUpdate("INSERT INTO testboolint VALUES(-1, null)");
    stmt.executeUpdate("INSERT INTO testboolint VALUES(9223372036854775807, null)");
    stmt.executeUpdate("INSERT INTO testboolint VALUES(-9223372036854775808, null)");

    // End Boolean Tests

    // TestUtil.createTable(con, "testbit", "a bit");

    TestUtil.createTable(con, "testnumeric", "t text, a numeric");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('1.0', '1.0')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('0.0', '0.0')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-1.0', '-1.0')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('1.2', '1.2')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-2.5', '-2.5')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('0.000000000000000000000000000990', '0.000000000000000000000000000990')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('10.0000000000099', '10.0000000000099')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('.10000000000000', '.10000000000000')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('.10', '.10')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('1.10000000000000', '1.10000000000000')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('99999.2', '99999.2')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('99999', '99999')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-99999.2', '-99999.2')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-99999', '-99999')");

    // Integer.MaxValue
    stmt.execute("INSERT INTO testnumeric VALUES('2147483647', '2147483647')");

    // Integer.MinValue
    stmt.execute("INSERT INTO testnumeric VALUES( '-2147483648', '-2147483648')");

    stmt.executeUpdate("INSERT INTO testnumeric VALUES('2147483648', '2147483648')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-2147483649', '-2147483649')");

    // Long.MaxValue
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('9223372036854775807','9223372036854775807')");
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('9223372036854775807.9', '9223372036854775807.9')");

    // Long.MinValue
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-9223372036854775808', '-9223372036854775808')");

    // Long.MaxValue +1
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('9223372036854775808', '9223372036854775808')");

    // Long.Minvalue -1
    stmt.executeUpdate("INSERT INTO testnumeric VALUES('-9223372036854775809', '-9223372036854775809')");

    stmt.executeUpdate("INSERT INTO testnumeric VALUES('10223372036850000000', '10223372036850000000')");

    TestUtil.createTable(con, "testpgobject", "id integer NOT NULL, d date, PRIMARY KEY (id)");
    stmt.execute("INSERT INTO testpgobject VALUES(1, '2010-11-3')");

    stmt.close();
  }

  @Override
  public void tearDown() throws SQLException {
    TestUtil.dropTable(con, "testrs");
    TestUtil.dropTable(con, "teststring");
    TestUtil.dropTable(con, "testint");
    // TestUtil.dropTable(con, "testbit");
    TestUtil.dropTable(con, "testboolstring");
    TestUtil.dropTable(con, "testboolfloat");
    TestUtil.dropTable(con, "testboolint");
    TestUtil.dropTable(con, "testnumeric");
    TestUtil.dropTable(con, "testpgobject");
    super.tearDown();
  }

  @Test
  public void testBackward() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    ResultSet rs = stmt.executeQuery("SELECT * FROM testrs");
    rs.afterLast();
    assertTrue(rs.previous());
    rs.close();
    stmt.close();
  }

  @Test
  public void testAbsolute() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    ResultSet rs = stmt.executeQuery("SELECT * FROM testrs");

    assertFalse(rs.absolute(0));
    assertEquals(0, rs.getRow());

    assertTrue(rs.absolute(-1));
    assertEquals(6, rs.getRow());

    assertTrue(rs.absolute(1));
    assertEquals(1, rs.getRow());

    assertFalse(rs.absolute(-10));
    assertEquals(0, rs.getRow());
    assertTrue(rs.next());
    assertEquals(1, rs.getRow());

    assertFalse(rs.absolute(10));
    assertEquals(0, rs.getRow());
    assertTrue(rs.previous());
    assertEquals(6, rs.getRow());

    stmt.close();
  }

  @Test
  public void testRelative() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    ResultSet rs = stmt.executeQuery("SELECT * FROM testrs");

    assertFalse(rs.relative(0));
    assertEquals(0, rs.getRow());
    assertTrue(rs.isBeforeFirst());

    assertTrue(rs.relative(2));
    assertEquals(2, rs.getRow());

    assertTrue(rs.relative(1));
    assertEquals(3, rs.getRow());

    assertTrue(rs.relative(0));
    assertEquals(3, rs.getRow());

    assertFalse(rs.relative(-3));
    assertEquals(0, rs.getRow());
    assertTrue(rs.isBeforeFirst());

    assertTrue(rs.relative(4));
    assertEquals(4, rs.getRow());

    assertTrue(rs.relative(-1));
    assertEquals(3, rs.getRow());

    assertFalse(rs.relative(6));
    assertEquals(0, rs.getRow());
    assertTrue(rs.isAfterLast());

    assertTrue(rs.relative(-4));
    assertEquals(3, rs.getRow());

    assertFalse(rs.relative(-6));
    assertEquals(0, rs.getRow());
    assertTrue(rs.isBeforeFirst());

    stmt.close();
  }

  @Test
  public void testEmptyResult() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    ResultSet rs = stmt.executeQuery("SELECT * FROM testrs where id=100");
    rs.beforeFirst();
    rs.afterLast();
    assertFalse(rs.first());
    assertFalse(rs.last());
    assertFalse(rs.next());
  }

  @Test
  public void testMaxFieldSize() throws SQLException {
    Statement stmt = con.createStatement();
    stmt.setMaxFieldSize(2);

    ResultSet rs = stmt.executeQuery("select * from testint");

    // max should not apply to the following since per the spec
    // it should apply only to binary and char/varchar columns
    rs.next();
    assertEquals("12345", rs.getString(1));
    // getBytes returns 5 bytes for txt transfer, 4 for bin transfer
    assertTrue(rs.getBytes(1).length >= 4);

    // max should apply to the following since the column is
    // a varchar column
    rs = stmt.executeQuery("select * from teststring");
    rs.next();
    assertEquals("12", rs.getString(1));
    assertEquals("12", new String(rs.getBytes(1)));
  }

  @Test
  public void testBooleanBool() throws SQLException {
    testBoolean("testbool", 0);
    testBoolean("testbool", 1);
    testBoolean("testbool", 5);
    testBoolean("testbool", -1);
  }

  @Test
  public void testBooleanString() throws SQLException {
    testBoolean("testboolstring", 0);
    testBoolean("testboolstring", 1);
    testBoolean("testboolstring", 5);
    testBoolean("testboolstring", -1);
  }

  @Test
  public void testBooleanFloat() throws SQLException {
    testBoolean("testboolfloat", 0);
    testBoolean("testboolfloat", 1);
    testBoolean("testboolfloat", 5);
    testBoolean("testboolfloat", -1);
  }

  @Test
  public void testBooleanInt() throws SQLException {
    testBoolean("testboolint", 0);
    testBoolean("testboolint", 1);
    testBoolean("testboolint", 5);
    testBoolean("testboolint", -1);
  }

  public void testBoolean(String table, int prepareThreshold) throws SQLException {
    PreparedStatement pstmt = con.prepareStatement("select a, b from " + table);
    ((org.postgresql.PGStatement) pstmt).setPrepareThreshold(prepareThreshold);
    ResultSet rs = pstmt.executeQuery();
    while (rs.next()) {
      rs.getBoolean(2);
      Boolean expected = rs.wasNull() ? null : rs.getBoolean(2); // Hack to get SQL NULL
      if (expected != null) {
        assertEquals(expected, rs.getBoolean(1));
      } else {
        // expected value with null are bad values
        try {
          rs.getBoolean(1);
          fail();
        } catch (SQLException e) {
          assertEquals(PSQLState.CANNOT_COERCE.getState(), e.getSQLState());
        }
      }
    }
    rs.close();
    pstmt.close();
  }

  @Test
  public void testGetBooleanJDBCCompliance() throws SQLException {
    // The JDBC specification in Table B-6 "Use of ResultSet getter Methods to Retrieve JDBC Data Types"
    // the getBoolean have this Supported JDBC Type: TINYINT, SMALLINT, INTEGER, BIGINT, REAL, FLOAT,
    // DOUBLE, DECIMAL, NUMERIC, BIT, BOOLEAN, CHAR, VARCHAR, LONGVARCHAR

    // There is no TINYINT in PostgreSQL
    testgetBoolean("int2"); // SMALLINT
    testgetBoolean("int4"); // INTEGER
    testgetBoolean("int8"); // BIGINT
    testgetBoolean("float4"); // REAL
    testgetBoolean("float8"); // FLOAT, DOUBLE
    testgetBoolean("numeric"); // DECIMAL, NUMERIC
    testgetBoolean("bpchar"); // CHAR
    testgetBoolean("varchar"); // VARCHAR
    testgetBoolean("text"); // LONGVARCHAR?
  }

  public void testgetBoolean(String dataType) throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("select 1::" + dataType + ", 0::" + dataType + ", 2::" + dataType);
    assertTrue(rs.next());
    assertTrue(rs.getBoolean(1));
    assertFalse(rs.getBoolean(2));

    try {
      // The JDBC ResultSet JavaDoc states that only 1 and 0 are valid values, so 2 should return error.
      rs.getBoolean(3);
      fail();
    } catch (SQLException e) {
      assertEquals(PSQLState.CANNOT_COERCE.getState(), e.getSQLState());
      // message can be 2 or 2.0 depending on whether binary or text
      final String message = e.getMessage();
      if (!"Cannot cast to boolean: \"2.0\"".equals(message)) {
        assertEquals("Cannot cast to boolean: \"2\"", message);
      }
    }
    rs.close();
    stmt.close();
  }

  @Test
  public void testgetBadBoolean() throws SQLException {
    testBadBoolean("'2017-03-13 14:25:48.130861'::timestamp", "2017-03-13 14:25:48.130861");
    testBadBoolean("'2017-03-13'::date", "2017-03-13");
    testBadBoolean("'2017-03-13 14:25:48.130861'::time", "14:25:48.130861");
    testBadBoolean("ARRAY[[1,0],[0,1]]", "{{1,0},{0,1}}");
    testBadBoolean("29::bit(4)", "1101");
  }

  @Test
  public void testGetBadUuidBoolean() throws SQLException {
    assumeTrue(TestUtil.haveMinimumServerVersion(con, ServerVersion.v8_3));
    testBadBoolean("'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11");
  }

  public void testBadBoolean(String select, String value) throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("select " + select);
    assertTrue(rs.next());
    try {
      rs.getBoolean(1);
      fail();
    } catch (SQLException e) {
      //binary transfer gets different error code and message
      if (org.postgresql.util.PSQLState.DATA_TYPE_MISMATCH.getState().equals(e.getSQLState())) {
        final String message = e.getMessage();
        if (!message.startsWith("Cannot convert the column of type ")) {
          fail(message);
        }
        if (!message.endsWith(" to requested type boolean.")) {
          fail(message);
        }
      } else {
        assertEquals(PSQLState.CANNOT_COERCE.getState(), e.getSQLState());
        assertEquals("Cannot cast to boolean: \"" + value + "\"", e.getMessage());
      }
    }
    rs.close();
    stmt.close();
  }

  @Test
  public void testgetByte() throws SQLException {
    ResultSet rs = con.createStatement().executeQuery("select a from testnumeric");

    assertTrue(rs.next());
    assertEquals(1, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(-1, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(-2, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(10, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getByte(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getByte(1));

    while (rs.next()) {
      try {
        rs.getByte(1);
        fail("Exception expected.");
      } catch (SQLException e) {
        assertEquals(e.getSQLState(), "22003");
      }
    }
    rs.close();
  }

  @Test
  public void testgetShort() throws SQLException {
    ResultSet rs = con.createStatement().executeQuery("select a from testnumeric");

    assertTrue(rs.next());
    assertEquals(1, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(-1, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(-2, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(10, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getShort(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getShort(1));

    while (rs.next()) {
      try {
        rs.getShort(1);
        fail("Exception expected.");
      } catch (SQLException e) {
      }
    }
    rs.close();
  }

  @Test
  public void testgetInt() throws SQLException {
    ResultSet rs = con.createStatement().executeQuery("select a from testnumeric");

    assertTrue(rs.next());
    assertEquals(1, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(-1, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(-2, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(10, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(0, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(1, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(99999, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(99999, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(-99999, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(-99999, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(Integer.MAX_VALUE, rs.getInt(1));

    assertTrue(rs.next());
    assertEquals(Integer.MIN_VALUE, rs.getInt(1));

    while (rs.next()) {
      try {
        rs.getInt(1);
        fail("Exception expected." + rs.getString(1));
      } catch (SQLException e) {
      }
    }
    rs.close();
    // test for Issue #2748
    rs = con.createStatement().executeQuery("select 2.0 :: double precision");
    assertTrue(rs.next());
    assertEquals(2, rs.getInt(1));
    rs.close();

  }

  @Test
  public void testgetLong() throws SQLException {
    ResultSet rs = null;

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.0'");
    assertTrue(rs.next());
    assertEquals(1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '0.0'");
    assertTrue(rs.next());
    assertEquals(0, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-1.0'");
    assertTrue(rs.next());
    assertEquals(-1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.2'");
    assertTrue(rs.next());
    assertEquals(1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2.5'");
    assertTrue(rs.next());
    assertEquals(-2, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '0.000000000000000000000000000990'");
    assertTrue(rs.next());
    assertEquals(0, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '10.0000000000099'");
    assertTrue(rs.next());
    assertEquals(10, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '.10000000000000'");
    assertTrue(rs.next());
    assertEquals(0, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '.10'");
    assertTrue(rs.next());
    assertEquals(0, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.10000000000000'");
    assertTrue(rs.next());
    assertEquals(1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '99999.2'");
    assertTrue(rs.next());
    assertEquals(99999, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '99999'");
    assertTrue(rs.next());
    assertEquals(99999, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-99999.2'");
    assertTrue(rs.next());
    assertEquals(-99999, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-99999'");
    assertTrue(rs.next());
    assertEquals(-99999, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '2147483647'");
    assertTrue(rs.next());
    assertEquals((Integer.MAX_VALUE), rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2147483648'");
    assertTrue(rs.next());
    assertEquals((Integer.MIN_VALUE), rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '2147483648'");
    assertTrue(rs.next());
    assertEquals(((long) Integer.MAX_VALUE) + 1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2147483649'");
    assertTrue(rs.next());
    assertEquals(((long) Integer.MIN_VALUE) - 1, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775807'");
    assertTrue(rs.next());
    assertEquals(Long.MAX_VALUE, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775807.9'");
    assertTrue(rs.next());
    assertEquals(Long.MAX_VALUE, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-9223372036854775808'");
    assertTrue(rs.next());
    assertEquals(Long.MIN_VALUE, rs.getLong(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775808'");
    assertTrue(rs.next());
    try {
      rs.getLong(1);
      fail("Exception expected. " + rs.getString(1));
    } catch (SQLException e) {
    }
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-9223372036854775809'");
    assertTrue(rs.next());
    try {
      rs.getLong(1);
      fail("Exception expected. " + rs.getString(1));
    } catch (SQLException e) {
    }
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '10223372036850000000'");
    assertTrue(rs.next());
    try {
      rs.getLong(1);
      fail("Exception expected. " + rs.getString(1));
    } catch (SQLException e) {
    }
    rs.close();

    rs = con.createStatement().executeQuery("select i, a from testboolfloat order by i");

    assertTrue(rs.next());
    assertEquals(1, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(0, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(1, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(0, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(1, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(-1, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(123, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(123, rs.getLong(2));

    assertTrue(rs.next());
    assertEquals(1, rs.getLong(2));

    assertTrue(rs.next());
    // the string value from database trims the significant digits, leading to larger variance than binary
    // the liberica jdk gets similar variance, even in forced binary mode
    assertEquals(9223371487098961921.0, rs.getLong(2), 1.0e11);

    assertTrue(rs.next());
    do {
      try {
        int row = rs.getInt(1);
        long l = rs.getLong(2);
        if ( row == 12 ) {
          assertEquals(9223371487098961920.0, l, 1.0e11);
        } else if ( row == 15 ) {
          assertEquals(-9223371487098961920.0, l, 1.0e11);
        } else {
          fail("Exception expected." + rs.getString(2));
        }
      } catch (SQLException e) {
      }
    } while (rs.next());

    rs.close();
  }

  @Test
  public void testgetBigDecimal() throws SQLException {
    ResultSet rs = null;

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.0'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(1.0), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '0.0'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(0.0), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-1.0'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(-1.0), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.2'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(1.2), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2.5'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(-2.5), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '0.000000000000000000000000000990'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("0.000000000000000000000000000990"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '10.0000000000099'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("10.0000000000099"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '.10000000000000'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("0.10000000000000"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '.10'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("0.10"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '1.10000000000000'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("1.10000000000000"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '99999.2'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(99999.2), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '99999'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(99999), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-99999.2'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(-99999.2), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-99999'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(-99999), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '2147483647'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(2147483647), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2147483648'");
    assertTrue(rs.next());
    assertEquals(BigDecimal.valueOf(-2147483648), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '2147483648'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("2147483648"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-2147483649'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("-2147483649"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775807'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("9223372036854775807"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775807.9'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("9223372036854775807.9"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-9223372036854775808'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("-9223372036854775808"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '9223372036854775808'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("9223372036854775808"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '-9223372036854775809'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("-9223372036854775809"), rs.getBigDecimal(1));
    rs.close();

    rs = con.createStatement().executeQuery("select a from testnumeric where t = '10223372036850000000'");
    assertTrue(rs.next());
    assertEquals(new BigDecimal("10223372036850000000"), rs.getBigDecimal(1));
    rs.close();
  }

  @Test
  public void testParameters() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
    stmt.setFetchSize(100);
    stmt.setFetchDirection(ResultSet.FETCH_UNKNOWN);

    ResultSet rs = stmt.executeQuery("SELECT * FROM testrs");

    assertEquals(ResultSet.CONCUR_UPDATABLE, stmt.getResultSetConcurrency());
    assertEquals(ResultSet.TYPE_SCROLL_SENSITIVE, stmt.getResultSetType());
    assertEquals(100, stmt.getFetchSize());
    assertEquals(ResultSet.FETCH_UNKNOWN, stmt.getFetchDirection());

    assertEquals(ResultSet.CONCUR_UPDATABLE, rs.getConcurrency());
    assertEquals(ResultSet.TYPE_SCROLL_SENSITIVE, rs.getType());
    if (!con.unwrap(PGConnection.class).getAdaptiveFetch()) {
      assertEquals(100, rs.getFetchSize(), "ResultSet.fetchSize should not change after query execution");
    }
    assertEquals(ResultSet.FETCH_UNKNOWN, rs.getFetchDirection());

    rs.close();
    stmt.close();
  }

  @Test
  public void testCreateStatementWithInvalidResultSetParams() throws SQLException {
    assertThrows(PSQLException.class, () -> con.createStatement(-1, -1,-1));
  }

  @Test
  public void testCreateStatementWithInvalidResultSetConcurrency() throws SQLException {
    assertThrows(PSQLException.class, () -> con.createStatement( ResultSet.TYPE_SCROLL_INSENSITIVE, -1) );
  }

  @Test
  public void testCreateStatementWithInvalidResultSetHoldability() throws SQLException {
    assertThrows(PSQLException.class, () -> con.createStatement( ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE, -1) );
  }

  @Test
  public void testPrepareStatementWithInvalidResultSetParams() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareStatement("SELECT id FROM testrs", -1, -1,-1));
  }

  @Test
  public void testPrepareStatementWithInvalidResultSetConcurrency() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareStatement("SELECT id FROM testrs", ResultSet.TYPE_SCROLL_INSENSITIVE, -1) );
  }

  @Test
  public void testPrepareStatementWithInvalidResultSetHoldability() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareStatement("SELECT id FROM testrs", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE, -1) );
  }

  @Test
  public void testPrepareCallWithInvalidResultSetParams() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareCall("SELECT id FROM testrs", -1, -1,-1));
  }

  @Test
  public void testPrepareCallWithInvalidResultSetConcurrency() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareCall("SELECT id FROM testrs", ResultSet.TYPE_SCROLL_INSENSITIVE, -1) );
  }

  @Test
  public void testPrepareCallWithInvalidResultSetHoldability() throws SQLException {
    assertThrows(PSQLException.class, () -> con.prepareCall("SELECT id FROM testrs", ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE, -1) );
  }

  @Test
  public void testZeroRowResultPositioning() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
    ResultSet rs =
        stmt.executeQuery("SELECT * FROM pg_database WHERE datname='nonexistentdatabase'");
    assertFalse(rs.previous());
    assertFalse(rs.previous());
    assertFalse(rs.next());
    assertFalse(rs.next());
    assertFalse(rs.next());
    assertFalse(rs.next());
    assertFalse(rs.next());
    assertFalse(rs.previous());
    assertFalse(rs.first());
    assertFalse(rs.last());
    assertEquals(0, rs.getRow());
    assertFalse(rs.absolute(1));
    assertFalse(rs.relative(1));
    assertFalse(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertFalse(rs.isFirst());
    assertFalse(rs.isLast());
    rs.close();
    stmt.close();
  }

  @Test
  public void testRowResultPositioning() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
    // Create a one row result set.
    ResultSet rs = stmt.executeQuery("SELECT * FROM pg_database WHERE datname='template1'");

    assertTrue(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertFalse(rs.isFirst());
    assertFalse(rs.isLast());

    assertTrue(rs.next());

    assertFalse(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertTrue(rs.isFirst());
    assertTrue(rs.isLast());

    assertFalse(rs.next());

    assertFalse(rs.isBeforeFirst());
    assertTrue(rs.isAfterLast());
    assertFalse(rs.isFirst());
    assertFalse(rs.isLast());

    assertTrue(rs.previous());

    assertFalse(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertTrue(rs.isFirst());
    assertTrue(rs.isLast());

    assertTrue(rs.absolute(1));

    assertFalse(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertTrue(rs.isFirst());
    assertTrue(rs.isLast());

    assertFalse(rs.absolute(0));

    assertTrue(rs.isBeforeFirst());
    assertFalse(rs.isAfterLast());
    assertFalse(rs.isFirst());
    assertFalse(rs.isLast());

    assertFalse(rs.absolute(2));

    assertFalse(rs.isBeforeFirst());
    assertTrue(rs.isAfterLast());
    assertFalse(rs.isFirst());
    assertFalse(rs.isLast());

    rs.close();
    stmt.close();
  }

  @Test
  public void testForwardOnlyExceptions() throws SQLException {
    // Test that illegal operations on a TYPE_FORWARD_ONLY resultset
    // correctly result in throwing an exception.
    Statement stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
    ResultSet rs = stmt.executeQuery("SELECT * FROM testnumeric");

    try {
      rs.absolute(1);
      fail("absolute() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }
    try {
      rs.afterLast();
      fail("afterLast() on a TYPE_FORWARD_ONLY resultset did not throw an exception on a TYPE_FORWARD_ONLY resultset");
    } catch (SQLException e) {
    }
    try {
      rs.beforeFirst();
      fail("beforeFirst() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }
    try {
      rs.first();
      fail("first() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }
    try {
      rs.last();
      fail("last() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }
    try {
      rs.previous();
      fail("previous() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }
    try {
      rs.relative(1);
      fail("relative() on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }

    try {
      rs.setFetchDirection(ResultSet.FETCH_REVERSE);
      fail("setFetchDirection(FETCH_REVERSE) on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }

    try {
      rs.setFetchDirection(ResultSet.FETCH_UNKNOWN);
      fail("setFetchDirection(FETCH_UNKNOWN) on a TYPE_FORWARD_ONLY resultset did not throw an exception");
    } catch (SQLException e) {
    }

    rs.close();
    stmt.close();
  }

  @Test
  public void testCaseInsensitiveFindColumn() throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT id, id AS \"ID2\" FROM testrs");
    assertEquals(1, rs.findColumn("id"));
    assertEquals(1, rs.findColumn("ID"));
    assertEquals(1, rs.findColumn("Id"));
    assertEquals(2, rs.findColumn("id2"));
    assertEquals(2, rs.findColumn("ID2"));
    assertEquals(2, rs.findColumn("Id2"));
    try {
      rs.findColumn("id3");
      fail("There isn't an id3 column in the ResultSet.");
    } catch (SQLException sqle) {
    }
  }

  @Test
  public void testGetOutOfBounds() throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT id FROM testrs");
    assertTrue(rs.next());

    try {
      rs.getInt(-9);
    } catch (SQLException sqle) {
    }

    try {
      rs.getInt(1000);
    } catch (SQLException sqle) {
    }
  }

  @Test
  public void testClosedResult() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
    ResultSet rs = stmt.executeQuery("SELECT id FROM testrs");
    rs.close();

    rs.close(); // Closing twice is allowed.
    try {
      rs.getInt(1);
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.getInt("id");
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.getType();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.wasNull();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.absolute(3);
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.isBeforeFirst();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.setFetchSize(10);
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.getMetaData();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.rowUpdated();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.updateInt(1, 1);
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.moveToInsertRow();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
    try {
      rs.clearWarnings();
      fail("Expected SQLException");
    } catch (SQLException e) {
    }
  }

  /*
   * The JDBC spec says when you have duplicate column names, the first one should be returned.
   */
  @Test
  public void testDuplicateColumnNameOrder() throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT 1 AS a, 2 AS a");
    assertTrue(rs.next());
    assertEquals(1, rs.getInt("a"));
  }

  @Test
  public void testTurkishLocale() throws SQLException {
    Locale current = Locale.getDefault();
    try {
      Locale.setDefault(new Locale("tr", "TR"));
      Statement stmt = con.createStatement();
      ResultSet rs = stmt.executeQuery("SELECT id FROM testrs");
      int sum = 0;
      while (rs.next()) {
        sum += rs.getInt("ID");
      }
      rs.close();
      assertEquals(25, sum);
    } finally {
      Locale.setDefault(current);
    }
  }

  @Test
  public void testUpdateWithPGobject() throws SQLException {
    Statement stmt =
        con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);

    ResultSet rs = stmt.executeQuery("select * from testpgobject where id = 1");
    assertTrue(rs.next());
    assertEquals("2010-11-03", rs.getDate("d").toString());

    PGobject pgobj = new PGobject();
    pgobj.setType("date");
    pgobj.setValue("2014-12-23");
    rs.updateObject("d", pgobj);
    rs.updateRow();
    rs.close();

    ResultSet rs1 = stmt.executeQuery("select * from testpgobject where id = 1");
    assertTrue(rs1.next());
    assertEquals("2014-12-23", rs1.getDate("d").toString());
    rs1.close();

    stmt.close();
  }

  /**
   * Test the behavior of the result set column mapping cache for simple statements.
   */
  @Test
  public void testStatementResultSetColumnMappingCache() throws SQLException {
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("select * from testrs");
    Map<String, Integer> columnNameIndexMap;
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    assertTrue(rs.next());
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    rs.getInt("ID");
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNotNull(columnNameIndexMap);
    rs.getInt("id");
    assertSame(columnNameIndexMap, getResultSetColumnNameIndexMap(rs));
    rs.close();
    rs = stmt.executeQuery("select * from testrs");
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    assertTrue(rs.next());
    rs.getInt("Id");
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNotNull(columnNameIndexMap);
    rs.close();
    stmt.close();
  }

  /**
   * Test the behavior of the result set column mapping cache for prepared statements.
   */
  @Test
  public void testPreparedStatementResultSetColumnMappingCache() throws SQLException {
    PreparedStatement pstmt = con.prepareStatement("SELECT id FROM testrs");
    ResultSet rs = pstmt.executeQuery();
    Map<String, Integer> columnNameIndexMap;
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    assertTrue(rs.next());
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    rs.getInt("id");
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNotNull(columnNameIndexMap);
    rs.close();
    rs = pstmt.executeQuery();
    assertTrue(rs.next());
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNull(columnNameIndexMap);
    rs.getInt("id");
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNotNull(columnNameIndexMap);
    rs.close();
    pstmt.close();
  }

  /**
   * Test the behavior of the result set column mapping cache for prepared statements once the
   * statement is named.
   */
  @Test
  public void testNamedPreparedStatementResultSetColumnMappingCache() throws SQLException {
    assumeTrue(preferQueryMode != PreferQueryMode.SIMPLE, "Simple protocol only mode does not support server-prepared statements");
    PreparedStatement pstmt = con.prepareStatement("SELECT id FROM testrs");
    ResultSet rs;
    // Make sure the prepared statement is named.
    // This ensures column mapping cache is reused across different result sets.
    for (int i = 0; i < 5; i++) {
      rs = pstmt.executeQuery();
      rs.close();
    }
    rs = pstmt.executeQuery();
    assertTrue(rs.next());
    rs.getInt("id");
    Map<String, Integer> columnNameIndexMap;
    columnNameIndexMap = getResultSetColumnNameIndexMap(rs);
    assertNotNull(columnNameIndexMap);
    rs.close();
    rs = pstmt.executeQuery();
    assertTrue(rs.next());
    rs.getInt("id");
    assertSame(columnNameIndexMap, getResultSetColumnNameIndexMap(rs), "Cached mapping should be same between different result sets of same named prepared statement");
    rs.close();
    pstmt.close();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Integer> getResultSetColumnNameIndexMap(ResultSet stmt) {
    try {
      Field columnNameIndexMapField = stmt.getClass().getDeclaredField("columnNameIndexMap");
      columnNameIndexMapField.setAccessible(true);
      return (Map<String, Integer>) columnNameIndexMapField.get(stmt);
    } catch (Exception e) {
    }
    return null;
  }

  private static class SelectTimestampManyTimes implements Callable<Integer> {

    private final Connection connection;
    private final int expectedYear;

    protected SelectTimestampManyTimes(Connection connection, int expectedYear) {
      this.connection = connection;
      this.expectedYear = expectedYear;
    }

    @Override
    public Integer call() throws SQLException {
      int year = expectedYear;
      try (Statement statement = connection.createStatement()) {
        for (int i = 0; i < 10; i++) {
          try (ResultSet resultSet = statement.executeQuery(
              String.format("SELECT unnest(array_fill('8/10/%d'::timestamp, ARRAY[%d]))",
                  expectedYear, 500))) {
            while (resultSet.next()) {
              Timestamp d = resultSet.getTimestamp(1);
              year = 1900 + d.getYear();
              if (year != expectedYear) {
                return year;
              }
            }
          }
        }
      }
      return year;
    }

  }

  @Test
  public void testTimestamp() throws InterruptedException, ExecutionException, TimeoutException {
    ExecutorService e = Executors.newFixedThreadPool(2);
    Integer year1 = 7777;
    Future<Integer> future1 = e.submit(new SelectTimestampManyTimes(con, year1));
    Integer year2 = 2017;
    Future<Integer> future2 = e.submit(new SelectTimestampManyTimes(con, year2));
    assertEquals(year1, future1.get(1, TimeUnit.MINUTES), "Year was changed in another thread");
    assertEquals(year2, future2.get(1, TimeUnit.MINUTES), "Year was changed in another thread");
    e.shutdown();
    e.awaitTermination(1, TimeUnit.MINUTES);
  }

}
