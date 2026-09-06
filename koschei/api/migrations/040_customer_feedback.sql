CREATE TABLE IF NOT EXISTS customer_feedback (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category text NOT NULL,
    subject text NOT NULL,
    message text NOT NULL,
    contact_email text,
    page_url text,
    user_agent text,
    status text NOT NULL DEFAULT 'new',
    owner_note text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT customer_feedback_category_check CHECK (category IN ('system_gap','bug','suggestion','usability','billing','security','other')),
    CONSTRAINT customer_feedback_status_check CHECK (status IN ('new','reviewing','planned','resolved','closed')),
    CONSTRAINT customer_feedback_subject_length_check CHECK (char_length(subject) BETWEEN 3 AND 160),
    CONSTRAINT customer_feedback_message_length_check CHECK (char_length(message) BETWEEN 10 AND 5000)
);

CREATE INDEX IF NOT EXISTS customer_feedback_status_created_idx
ON customer_feedback (status, created_at DESC);

CREATE INDEX IF NOT EXISTS customer_feedback_created_idx
ON customer_feedback (created_at DESC);
