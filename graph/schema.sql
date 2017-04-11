create table grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category int,
  action int,
  node varchar,
  parent varchar
)
--
create table nodes (
  name varchar PRIMARY KEY
)
--
create table node_parents (
  name varchar PRIMARY KEY,
  parent_name varchar
)
