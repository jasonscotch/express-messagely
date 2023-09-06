/** User class for message.ly */

const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    let result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      RETURNING username, password, first_name, last_name, phone
      `, [username, hashedPassword, first_name, last_name, phone]);
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password
      FROM users
      WHERE username = $1`,
      [username]
    );
    let user = result.rows[0];
    return user && await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at = current_timestamp
      WHERE username = $1
      RETURNING username
      `, [username]);
    if (!result.rows[0]) {
      throw new ExpressError(`No such user exists: ${username}`, 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users
      ORDER BY first_name
      `);
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1
    `, [username]);
    if (!result.rows[0]) {
      throw new ExpressError(`No such user exists: ${username}`, 404);
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(`
      SELECT u.username, u.first_name, u.last_name, u.phone,
      m.id, m.to_username, m.body, m.sent_at, m.read_at
      FROM users AS u
      JOIN messages AS m ON u.username = m.to_username
      WHERE m.from_username = $1
    `, [username]);
    
    if (results.rows.length === 0) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return results.rows.map(row => ({
      id: row.id,
      to_user: {
        username: row.to_username,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone,
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(`
      SELECT u.username, u.first_name, u.last_name, u.phone,
      m.id, m.from_username, m.body, m.sent_at, m.read_at
      FROM users AS u
      JOIN messages AS m ON u.username = m.from_username
      WHERE m.to_username = $1
    `, [username]);

    if (results.rows.length === 0) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return results.rows.map(row => ({
      id: row.id,
      from_user: {
        username: row.from_username,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone,
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at,
    }));
  }
}


module.exports = User;