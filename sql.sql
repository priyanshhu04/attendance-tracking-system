-- Create users table
CREATE TABLE users ( 
	id INT AUTO_INCREMENT PRIMARY KEY , 
	user_id VARCHAR (255) UNIQUE NOT NULL , 
	username VARCHAR (255) NOT NULL, 
	email VARCHAR (255) NOT NULL , 
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Create attendance table
CREATE TABLE attendance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    check_in_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'Present',
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
-- Sample data for testing
INSERT INTO users (user_id, username, email) VALUES 
('user123', 'John Doe', 'john@example.com'),
('user456', 'Jane Smith', 'jane@example.com');