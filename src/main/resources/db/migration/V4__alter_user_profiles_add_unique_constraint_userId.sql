ALTER TABLE user_profiles
ADD CONSTRAINT uq_user_profiles_user_id UNIQUE (user_id);
