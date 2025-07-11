/*
 * Copyright (c) 2016, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.replication;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.postgresql.PGConnection;
import org.postgresql.core.BaseConnection;
import org.postgresql.core.ServerVersion;
import org.postgresql.test.TestUtil;
import org.postgresql.test.annotations.DisabledIfServerVersionBelow;
import org.postgresql.test.annotations.tags.Replication;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;

@Replication
@DisabledIfServerVersionBelow("9.4")
class PhysicalReplicationTest {

  private static final String SLOT_NAME = "pgjdbc_physical_replication_slot";

  private Connection replConnection;
  private Connection sqlConnection;

  @BeforeEach
  void setUp() throws Exception {
    sqlConnection = TestUtil.openPrivilegedDB();
    //DriverManager.setLogWriter(new PrintWriter(System.out));
    replConnection = TestUtil.openReplicationConnection();
    TestUtil.createTable(sqlConnection, "test_physic_table",
        "pk serial primary key, name varchar(100)");
    TestUtil.recreatePhysicalReplicationSlot(sqlConnection, SLOT_NAME);
  }

  @AfterEach
  void tearDown() throws Exception {
    replConnection.close();
    TestUtil.dropTable(sqlConnection, "test_physic_table");
    TestUtil.dropReplicationSlot(sqlConnection, SLOT_NAME);
    sqlConnection.close();
  }

  @Test
  void receiveChangesWithoutReplicationSlot() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    Statement st = sqlConnection.createStatement();
    st.execute("insert into test_physic_table(name) values('previous value')");
    st.close();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withStartPosition(lsn)
            .start();

    ByteBuffer read = stream.read();

    assertThat("Physical replication can be start without replication slot",
        read, CoreMatchers.notNullValue()
    );
  }

  @Test
  void receiveChangesWithReplicationSlot() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    Statement st = sqlConnection.createStatement();
    st.execute("insert into test_physic_table(name) values('previous value')");
    st.close();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    ByteBuffer read = stream.read();

    assertThat(read, CoreMatchers.notNullValue());
  }

  @Test
  void afterStartStreamingDBSlotStatusActive() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    boolean isActive = isActiveOnView();
    stream.close();

    assertThat(
        "After start streaming, database status should be update on view pg_replication_slots to active",
        isActive, equalTo(true)
    );
  }

  @Test
  void afterCloseReplicationStreamDBSlotStatusNotActive() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    boolean isActive = isActiveOnView();
    assumeTrue(isActive, "isActive");

    stream.close();

    isActive = isActiveOnView();
    assertThat(
        "Execute close method on PGREplicationStream should lead to stop replication, "
            + "as result we wait that on view pg_replication_slots status for slot will change to no active",
        isActive, equalTo(false)
    );
  }

  @Test
  void walRecordCanBeRepeatBeRestartReplication() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    Statement st = sqlConnection.createStatement();
    st.execute("insert into test_physic_table(name) values('previous value')");
    st.close();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    byte[] first = toByteArray(stream.read());
    stream.close();

    //reopen stream
    stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    byte[] second = toByteArray(stream.read());
    stream.close();

    boolean arrayEquals = Arrays.equals(first, second);
    assertThat("On same replication connection we can restart replication from already "
            + "received LSN if they not recycled yet on backend",
        arrayEquals, CoreMatchers.equalTo(true)
    );
  }

  @Test
  void restartPhysicalReplicationWithoutRepeatMessage() throws Exception {
    PGConnection pgConnection = (PGConnection) replConnection;

    LogSequenceNumber lsn = getCurrentLSN();

    Statement st = sqlConnection.createStatement();
    st.execute("insert into test_physic_table(name) values('first value')");
    st.close();

    PGReplicationStream stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(lsn)
            .start();

    byte[] streamOneFirstPart = toByteArray(stream.read());
    LogSequenceNumber restartLSN = stream.getLastReceiveLSN();

    st = sqlConnection.createStatement();
    st.execute("insert into test_physic_table(name) values('second value')");
    st.close();

    byte[] streamOneSecondPart = toByteArray(stream.read());
    stream.close();

    //reopen stream
    stream =
        pgConnection
            .getReplicationAPI()
            .replicationStream()
            .physical()
            .withSlotName(SLOT_NAME)
            .withStartPosition(restartLSN)
            .start();

    byte[] streamTwoFirstPart = toByteArray(stream.read());
    stream.close();

    boolean arrayEquals = Arrays.equals(streamOneSecondPart, streamTwoFirstPart);
    assertThat("Interrupt physical replication and restart from lastReceiveLSN should not "
            + "lead to repeat messages skip part of them",
        arrayEquals, CoreMatchers.equalTo(true)
    );
  }

  private boolean isActiveOnView() throws SQLException {
    boolean result = false;
    Statement st = sqlConnection.createStatement();
    ResultSet
        rs =
        st.executeQuery("select * from pg_replication_slots where slot_name = '" + SLOT_NAME + "'");
    if (rs.next()) {
      result = rs.getBoolean("active");
    }
    rs.close();
    st.close();
    return result;
  }

  private static byte[] toByteArray(ByteBuffer buffer) {
    int offset = buffer.arrayOffset();
    byte[] source = buffer.array();
    return Arrays.copyOfRange(source, offset, source.length);
  }

  private LogSequenceNumber getCurrentLSN() throws SQLException {
    Statement st = sqlConnection.createStatement();
    ResultSet rs = null;
    try {
      rs = st.executeQuery("select "
          + (((BaseConnection) sqlConnection).haveMinimumServerVersion(ServerVersion.v10)
          ? "pg_current_wal_lsn()" : "pg_current_xlog_location()"));

      if (rs.next()) {
        String lsn = rs.getString(1);
        return LogSequenceNumber.valueOf(lsn);
      } else {
        return LogSequenceNumber.INVALID_LSN;
      }
    } finally {
      if (rs != null) {
        rs.close();
      }
      st.close();
    }
  }
}
