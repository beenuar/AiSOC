-- Depth plan wave 2, item 1.6: anonymizer and hosting classes at ingest.
--
-- Ingest stamps the class of a public source address from a pinned local
-- dataset (services/ingest/internal/activity/ipclass) and fusion carries it
-- onto the alert row. These two columns are what the console and the
-- investigation rail read.
--
-- Nullable on purpose, and the null means "the dataset had no entry". It
-- does NOT mean "this address is ordinary". Three of the five classes --
-- vpn, public_proxy and residential_proxy -- ship with no records because no
-- source for them survived the licence check, so an unclassified address is
-- the ordinary case. Every surface renders null as unknown; a boolean column
-- here would have forced a false that the data cannot support.
--
-- The dataset version is stored beside the class rather than inferred from
-- the alert's date. The dataset is refreshed, an address changes class over
-- time, and an analyst re-reading a six-month-old alert needs to know which
-- snapshot said so. Without it a reclassification and a change in behaviour
-- are indistinguishable in a historical query.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS src_ip_class TEXT,
    ADD COLUMN IF NOT EXISTS src_ip_class_dataset_version TEXT;

COMMENT ON COLUMN alerts.src_ip_class IS
    'Anonymizer or hosting class of src_ip from the pinned ingest dataset: vpn, tor_exit, public_proxy, residential_proxy or hosting_provider. NULL means the dataset had no entry, never that the address is ordinary.';
COMMENT ON COLUMN alerts.src_ip_class_dataset_version IS
    'Version of the IP classification dataset that produced src_ip_class. A class with no version cannot be dated, and the dataset is refreshed.';

-- Partial index: the overwhelming majority of rows are NULL (the dataset
-- covers two of five classes and only public addresses), so an index over
-- every row would be mostly empty entries. The queries that matter are
-- "show me alerts from an anonymizer" and the per-class counts on the
-- triage queue, both of which only ever look at non-null rows.
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip_class
    ON alerts (tenant_id, src_ip_class)
    WHERE src_ip_class IS NOT NULL;

-- No new RLS policy: these are columns on `alerts`, which already carries a
-- tenant-scoped policy, and a column addition inherits it.
