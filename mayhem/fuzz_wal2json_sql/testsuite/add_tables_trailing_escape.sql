select 1;
select pg_logical_slot_peek_changes($$fuzz$$, NULL, NULL, $$add-tables$$, $$a\$$);
