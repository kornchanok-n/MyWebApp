# MyWebApp

simple Web application with login / register function and microsoft account login

how to use MyWebApp

1. clone this repository
2. execute "npm install"
3. download MAMP to start MySQL server
4. create your database and add user table by SQL command
"CREATE TABLE users (
    id int(10) NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name varchar(50) NOT NULL,
    email varchar(50) NOT NULL UNIQUE KEY,
    password varchar(255) NOT NULL
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
5. execute "npm run dev"
6. go to "localhost:3000" and see how it work
