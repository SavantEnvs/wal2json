create schema "Sch ""q";
create domain "Sch ""q"."my""dom" as text check (value <> 'x');
create table "Sch ""q"."T 1" (a int primary key, b "Sch ""q"."my""dom" default 'd"ef', c bytea, d numeric(10,2), e text[]);
insert into "Sch ""q"."T 1" values (1, 'he said "hi"\', '\x00ff', 3.14, '{a,"b c"}');
update "Sch ""q"."T 1" set b = 'z' where a = 1;
delete from "Sch ""q"."T 1";
select pg_logical_emit_message(true, 'pre"fix', 'con\tent');
truncate "Sch ""q"."T 1";
