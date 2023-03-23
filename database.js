const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./login.db', sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Database created.')
});

function initDb() {
  db.serialize(function () {
    db.run("DROP TABLE IF EXISTS users;");
    db.run("CREATE TABLE IF NOT EXISTS users(username TEXT NOT NULL PRIMARY KEY, name TEXT, role TEXT CHECK(role in('STUDENT1', 'STUDENT2', 'TEACHER','ADMIN')), password TEXT NOT NULL);");
  })
}

function nameExists(usernameToSearchFor) {
  let sql = "SELECT username FROM users"
  return new Promise((myResolve, myReject) => {
      db.all(sql, (err, rows) => {
          if (err) {
              console.log("ERROR")
          }
          else {
              for (let i = 0; i < rows.length; i++) {
                  if (rows[i].username === usernameToSearchFor) {
                      myResolve(true)
                  }
              }
              myResolve(false)
          }
      })
  });
}

function getPasswordForUser(usernameToSearchFor) {
  return new Promise((resolve, reject) => {
      const sql = "SELECT password FROM users where username = ?";
      db.get(sql, [usernameToSearchFor], (err, row) => {
          if (err) {
              return reject(err);
          }
          if (!row) {
              return reject(new Error("User was not found, please try again!"));
          }
          resolve(row.password);
      });
  });
}

async function addUser(username, name, role, password) {
  if (await nameExists(username)) {
    console.log("Username is already taken, please try another one")
}
else {
      return new Promise((resolve, reject) => {
          db.run('INSERT INTO users (username, name, role, password) VALUES (?, ?, ?, ?)', [username, name, role, password], (err) => {
              if (err) {
                  return reject(err);
              }
              resolve();
          });
      });
  }
}

function getAllUsers() {
  return new Promise((resolve, reject) => {
    db.all("SELECT * FROM users", (err, res) => {
      if (err) {
        reject(err);
      } else {
        resolve(res);
      }
    });
  });
}



module.exports = {addUser, getAllUsers}