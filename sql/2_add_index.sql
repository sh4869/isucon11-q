create index jia_isu_uuid_index on isu_condition(jia_isu_uuid DESC);
create index jia_isu_uuid_and_timpestamp__index on isu_condition(jia_isu_uuid, timestamp DESC);