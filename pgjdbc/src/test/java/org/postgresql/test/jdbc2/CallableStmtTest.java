/*
 * Copyright (c) 2004, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.test.jdbc2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.postgresql.test.TestUtil;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.sql.Array;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.sql.Types;

/**
 * CallableStatement tests.
 *
 * @author Paul Bethe
 */
public class CallableStmtTest extends BaseTest4 {
  @BeforeAll
  public static void beforeClass() throws Exception {
    try (Connection con = TestUtil.openDB()) {
      assumeCallableStatementsSupported(con);
    }
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    TestUtil.createTable(con, "int_table", "id int");
    Statement stmt = con.createStatement();
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getString (varchar) "
        + "RETURNS varchar AS ' DECLARE inString alias for $1; begin "
        + "return ''bob''; end; ' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getDouble (float) "
        + "RETURNS float AS ' DECLARE inString alias for $1; begin "
        + "return 42.42; end; ' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getVoid (float) "
        + "RETURNS void AS ' DECLARE inString alias for $1; begin "
        + " return; end; ' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getInt (int) RETURNS int "
        + " AS 'DECLARE inString alias for $1; begin "
        + "return 42; end;' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getShort (int2) RETURNS int2 "
        + " AS 'DECLARE inString alias for $1; begin "
        + "return 42; end;' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getNumeric (numeric) "
        + "RETURNS numeric AS ' DECLARE inString alias for $1; "
        + "begin return 42; end; ' LANGUAGE plpgsql;");

    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getNumericWithoutArg() "
        + "RETURNS numeric AS '  "
        + "begin return 42; end; ' LANGUAGE plpgsql;");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__getarray() RETURNS int[] as "
        + "'SELECT ''{1,2}''::int[];' LANGUAGE sql");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__raisenotice() RETURNS int as "
        + "'BEGIN RAISE NOTICE ''hello'';  RAISE NOTICE ''goodbye''; RETURN 1; END;' LANGUAGE plpgsql");
    stmt.execute(
        "CREATE OR REPLACE FUNCTION testspg__insertInt(int) RETURNS int as "
        + "'BEGIN INSERT INTO int_table(id) VALUES ($1); RETURN 1; END;' LANGUAGE plpgsql");
    stmt.close();
  }

  @Override
  public void tearDown() throws SQLException {
    Statement stmt = con.createStatement();
    TestUtil.dropTable(con, "int_table");
    stmt.execute("drop FUNCTION testspg__getString (varchar);");
    stmt.execute("drop FUNCTION testspg__getDouble (float);");
    stmt.execute("drop FUNCTION testspg__getVoid(float);");
    stmt.execute("drop FUNCTION testspg__getInt (int);");
    stmt.execute("drop FUNCTION testspg__getShort(int2)");
    stmt.execute("drop FUNCTION testspg__getNumeric (numeric);");

    stmt.execute("drop FUNCTION testspg__getNumericWithoutArg ();");
    stmt.execute("DROP FUNCTION testspg__getarray();");
    stmt.execute("DROP FUNCTION testspg__raisenotice();");
    stmt.execute("DROP FUNCTION testspg__insertInt(int);");
    super.tearDown();
  }

  final String func = "{ ? = call ";
  final String pkgName = "testspg__";

  @Test
  public void testGetUpdateCount() throws SQLException {
    CallableStatement call = con.prepareCall(func + pkgName + "getDouble (?) }");
    call.setDouble(2, 3.04);
    call.registerOutParameter(1, Types.DOUBLE);
    call.execute();
    assertEquals(-1, call.getUpdateCount());
    assertNull(call.getResultSet());
    assertEquals(42.42, call.getDouble(1), 0.00001);
    call.close();

    // test without an out parameter
    call = con.prepareCall("{ call " + pkgName + "getDouble(?) }");
    call.setDouble(1, 3.04);
    call.execute();
    assertEquals(-1, call.getUpdateCount());
    ResultSet rs = call.getResultSet();
    assertNotNull(rs);
    assertTrue(rs.next());
    assertEquals(42.42, rs.getDouble(1), 0.00001);
    assertFalse(rs.next());
    rs.close();

    assertEquals(-1, call.getUpdateCount());
    assertFalse(call.getMoreResults());
    call.close();
  }

  @Test
  public void testGetDouble() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getDouble (?) }");
    call.setDouble(2, 3.04);
    call.registerOutParameter(1, Types.DOUBLE);
    call.execute();
    assertEquals(42.42, call.getDouble(1), 0.00001);

    // test without an out parameter
    call = con.prepareCall("{ call " + pkgName + "getDouble(?) }");
    call.setDouble(1, 3.04);
    call.execute();

    call = con.prepareCall("{ call " + pkgName + "getVoid(?) }");
    call.setDouble(1, 3.04);
    call.execute();
  }

  @Test
  public void testGetInt() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getInt (?) }");
    call.setInt(2, 4);
    call.registerOutParameter(1, Types.INTEGER);
    call.execute();
    assertEquals(42, call.getInt(1));
  }

  @Test
  public void testGetShort() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getShort (?) }");
    call.setShort(2, (short) 4);
    call.registerOutParameter(1, Types.SMALLINT);
    call.execute();
    assertEquals(42, call.getShort(1));
  }

  @Test
  public void testGetNumeric() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getNumeric (?) }");
    call.setBigDecimal(2, new java.math.BigDecimal(4));
    call.registerOutParameter(1, Types.NUMERIC);
    call.execute();
    assertEquals(new BigDecimal(42), call.getBigDecimal(1));
  }

  @Test
  public void testGetNumericWithoutArg() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getNumericWithoutArg () }");
    call.registerOutParameter(1, Types.NUMERIC);
    call.execute();
    assertEquals(new BigDecimal(42), call.getBigDecimal(1));
  }

  @Test
  public void testGetString() throws Throwable {
    CallableStatement call = con.prepareCall(func + pkgName + "getString (?) }");
    call.setString(2, "foo");
    call.registerOutParameter(1, Types.VARCHAR);
    call.execute();
    assertEquals("bob", call.getString(1));

  }

  @Test
  public void testGetArray() throws SQLException {
    CallableStatement call = con.prepareCall(func + pkgName + "getarray()}");
    call.registerOutParameter(1, Types.ARRAY);
    call.execute();
    Array arr = call.getArray(1);
    ResultSet rs = arr.getResultSet();
    assertTrue(rs.next());
    assertEquals(1, rs.getInt(1));
    assertTrue(rs.next());
    assertEquals(2, rs.getInt(1));
    assertFalse(rs.next());
  }

  @Test
  public void testRaiseNotice() throws SQLException {
    Statement statement = con.createStatement();
    statement.execute("SET SESSION client_min_messages = 'NOTICE'");
    CallableStatement call = con.prepareCall(func + pkgName + "raisenotice()}");
    call.registerOutParameter(1, Types.INTEGER);
    call.execute();
    SQLWarning warn = call.getWarnings();
    assertNotNull(warn);
    assertEquals("hello", warn.getMessage());
    warn = warn.getNextWarning();
    assertNotNull(warn);
    assertEquals("goodbye", warn.getMessage());
    assertEquals(1, call.getInt(1));
  }

  @Test
  public void testWasNullBeforeFetch() throws SQLException {
    CallableStatement cs = con.prepareCall("{? = call lower(?)}");
    cs.registerOutParameter(1, Types.VARCHAR);
    cs.setString(2, "Hi");
    try {
      cs.wasNull();
      fail("expected exception");
    } catch (Exception e) {
      assertInstanceOf(SQLException.class, e);
    }
  }

  @Test
  public void testFetchBeforeExecute() throws SQLException {
    CallableStatement cs = con.prepareCall("{? = call lower(?)}");
    cs.registerOutParameter(1, Types.VARCHAR);
    cs.setString(2, "Hi");
    try {
      cs.getString(1);
      fail("expected exception");
    } catch (Exception e) {
      assertInstanceOf(SQLException.class, e);
    }
  }

  @Test
  public void testFetchWithNoResults() throws SQLException {
    CallableStatement cs = con.prepareCall("{call now()}");
    cs.execute();
    try {
      cs.getObject(1);
      fail("expected exception");
    } catch (Exception e) {
      assertInstanceOf(SQLException.class, e);
    }
  }

  @Test
  public void testBadStmt() throws Throwable {
    tryOneBadStmt("{ ?= " + pkgName + "getString (?) }");
    tryOneBadStmt("{ ?= call getString (?) ");
    tryOneBadStmt("{ = ? call getString (?); }");
  }

  protected void tryOneBadStmt(String sql) throws SQLException {
    try {
      con.prepareCall(sql);
      fail("Bad statement (" + sql + ") was not caught.");

    } catch (SQLException e) {
    }
  }

  @Test
  public void testBatchCall() throws SQLException {
    CallableStatement call = con.prepareCall("{ call " + pkgName + "insertInt(?) }");
    call.setInt(1, 1);
    call.addBatch();
    call.setInt(1, 2);
    call.addBatch();
    call.setInt(1, 3);
    call.addBatch();
    call.executeBatch();
    call.close();

    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT id FROM int_table ORDER BY id");
    assertTrue(rs.next());
    assertEquals(1, rs.getInt(1));
    assertTrue(rs.next());
    assertEquals(2, rs.getInt(1));
    assertTrue(rs.next());
    assertEquals(3, rs.getInt(1));
    assertFalse(rs.next());
  }

}
