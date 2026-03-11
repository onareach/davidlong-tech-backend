-- Migration: Seed branches and mysteries for Research Studio
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/004_seed_research_studio.sql

-- Seed branches

INSERT INTO tbl_research_branches (
    research_branch_handle,
    research_branch_name,
    research_branch_description
) VALUES
('algebra_of_qualities', 'Algebra of Qualities', 'Research on qualities, harmony, and value.'),
('information_and_matter', 'Information and Matter', 'Exploration of the relationship between information and physical form.'),
('knowledge_systems', 'Knowledge Systems', 'Systems for organizing knowledge and research.'),
('teaching_and_learning', 'Teaching and Learning', 'Pedagogy and educational technology.'),
('language_and_formula', 'Language and Formula', 'Formulas as language and symbolic structure.'),
('digital_fabrication', 'Digital Fabrication', 'Transforming digital information into physical objects via CNC, CAD, etc.')
ON CONFLICT (research_branch_handle) DO NOTHING;

-- Seed mysteries

INSERT INTO tbl_research_mysteries (
    research_mystery_handle,
    research_mystery_question,
    research_mystery_description
) VALUES
('math_effectiveness', 'Why does mathematics describe reality so effectively?', 'Inspired by Wigner''s famous observation about mathematics and nature.'),
('information_to_matter', 'How does information become matter?', 'Exploring the transformation of digital information into physical form.'),
('mystery_and_learning', 'Why do mysteries stimulate learning?', 'Investigating the role of mystery in cognition and engagement.')
ON CONFLICT (research_mystery_handle) DO NOTHING;
