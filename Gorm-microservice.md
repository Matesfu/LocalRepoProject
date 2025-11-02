# 🏗️ Complete Guide: GORM + PostgreSQL Microservices in Go

I'll walk you through building a production-ready microservice architecture with GORM, PostgreSQL, and Fiber API Gateway. This is comprehensive—let's build it step by step.

---

## 📋 Table of Contents

1. [Project Structure Setup](#project-structure)
2. [Environment Configuration](#environment-configuration)
3. [Database Connection & GORM Initialization](#database-connection)
4. [Migrations (Production-Ready)](#migrations)
5. [Models & Repository Layer](#models--repository)
6. [CRUD Operations & Service Layer](#crud-operations)
7. [Controllers & Routes](#controllers--routes)
8. [API Gateway Integration](#api-gateway)
9. [Advanced: Transactions & Performance](#advanced-topics)
10. [Best Practices Summary](#best-practices)

---

## 🗂️ Project Structure Setup {#project-structure}

Here's the complete folder hierarchy:

```
microservices/
├── gateway/
│   ├── cmd/
│   │   └── main.go
│   ├── internal/
│   │   ├── routes/
│   │   │   └── router.go
│   │   └── proxy/
│   │       └── handler.go
│   ├── .env
│   └── go.mod
├── services/
│   ├── user-service/
│   │   ├── cmd/
│   │   │   └── main.go
│   │   ├── internal/
│   │   │   ├── controller/
│   │   │   │   └── user_controller.go
│   │   │   ├── model/
│   │   │   │   └── user.go
│   │   │   ├── repository/
│   │   │   │   └── user_repository.go
│   │   │   ├── service/
│   │   │   │   └── user_service.go
│   │   │   ├── database/
│   │   │   │   ├── connection.go
│   │   │   │   └── migration.go
│   │   │   ├── routes/
│   │   │   │   └── user_routes.go
│   │   │   └── middleware/
│   │   │       └── logger.go
│   │   ├── .env
│   │   ├── go.mod
│   │   └── Makefile
│   ├── auth-service/
│   └── payment-service/
├── pkg/
│   ├── config/
│   │   └── config.go
│   ├── logger/
│   │   └── logger.go
│   └── middleware/
│       └── cors.go
└── docker-compose.yml
```

---

## 🔐 Environment Configuration {#environment-configuration}

### Step 1: Create Config Package

**File: `pkg/config/config.go`**

```go
package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// DatabaseConfig holds all database-related configuration
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// AppConfig holds application-level configuration
type AppConfig struct {
	Database DatabaseConfig
	Port     string
	Env      string
}

// LoadConfig loads environment variables using viper or godotenv
func LoadConfig(envFile string) (*AppConfig, error) {
	// Try loading from .env file
	viper.SetConfigFile(envFile)
	viper.AutomaticEnv() // Override with environment variables
	viper.SetDefault("PORT", "8000")
	viper.SetDefault("ENVIRONMENT", "development")
	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_PORT", "5432")
	viper.SetDefault("DB_SSLMODE", "disable")

	if err := viper.ReadInConfig(); err != nil {
		// If .env file not found, that's okay—use env vars or defaults
		fmt.Println("⚠️  .env file not found, using environment variables")
	}

	config := &AppConfig{
		Port: viper.GetString("PORT"),
		Env:  viper.GetString("ENVIRONMENT"),
		Database: DatabaseConfig{
			Host:     viper.GetString("DB_HOST"),
			Port:     viper.GetString("DB_PORT"),
			User:     viper.GetString("DB_USER"),
			Password: viper.GetString("DB_PASSWORD"),
			DBName:   viper.GetString("DB_NAME"),
			SSLMode:  viper.GetString("DB_SSLMODE"),
		},
	}

	// Validate required fields
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

// validateConfig ensures all critical config values are present
func validateConfig(config *AppConfig) error {
	requiredFields := []string{
		config.Database.Host,
		config.Database.User,
		config.Database.Password,
		config.Database.DBName,
	}

	for _, field := range requiredFields {
		if field == "" {
			return fmt.Errorf("❌ missing required database configuration")
		}
	}

	return nil
}
```

### Step 2: Create Logger Package

**File: `pkg/logger/logger.go`**

```go
package logger

import (
	"log"
	"os"
)

// Logger is a simple structured logger
type Logger struct {
	infoLog  *log.Logger
	errorLog *log.Logger
	warnLog  *log.Logger
}

// New creates a new logger instance
func New() *Logger {
	return &Logger{
		infoLog:  log.New(os.Stdout, "ℹ️  [INFO] ", log.LstdFlags),
		errorLog: log.New(os.Stderr, "❌ [ERROR] ", log.LstdFlags),
		warnLog:  log.New(os.Stdout, "⚠️  [WARN] ", log.LstdFlags),
	}
}

// Info logs informational messages
func (l *Logger) Info(msg string) {
	l.infoLog.Println(msg)
}

// Error logs error messages
func (l *Logger) Error(msg string) {
	l.errorLog.Println(msg)
}

// Warn logs warning messages
func (l *Logger) Warn(msg string) {
	l.warnLog.Println(msg)
}

// Infof logs formatted informational messages
func (l *Logger) Infof(format string, args ...interface{}) {
	l.infoLog.Printf(format+"\n", args...)
}

// Errorf logs formatted error messages
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.errorLog.Printf(format+"\n", args...)
}
```

### Step 3: Environment File

**File: `services/user-service/.env`**

```bash
# Application
PORT=3001
ENVIRONMENT=development

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=user_service_db
DB_SSLMODE=disable

# Connection Pool
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=5
DB_CONN_MAX_LIFETIME=5m
```

---

## 🔌 Database Connection & GORM Initialization {#database-connection}

### Step 1: Database Connection

**File: `services/user-service/internal/database/connection.go`**

```go
package database

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitializeDB initializes a GORM database connection to PostgreSQL
func InitializeDB() (*gorm.DB, error) {
	// Build PostgreSQL DSN (Data Source Name)
	dsn := buildDSN()

	// Open database connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		// Logger configuration
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		return nil, fmt.Errorf("❌ failed to connect to database: %w", err)
	}

	// Get the underlying SQL database for connection pooling
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("❌ failed to get database instance: %w", err)
	}

	// Configure connection pool for production
	maxOpenConns := viper.GetInt("DB_MAX_OPEN_CONNS")
	if maxOpenConns == 0 {
		maxOpenConns = 25
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)

	maxIdleConns := viper.GetInt("DB_MAX_IDLE_CONNS")
	if maxIdleConns == 0 {
		maxIdleConns = 5
	}
	sqlDB.SetMaxIdleConns(maxIdleConns)

	connMaxLifetime := viper.GetDuration("DB_CONN_MAX_LIFETIME")
	if connMaxLifetime == 0 {
		connMaxLifetime = 5 * time.Minute
	}
	sqlDB.SetConnMaxLifetime(connMaxLifetime)

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("❌ failed to ping database: %w", err)
	}

	log.Println("✅ Database connection established successfully")
	return db, nil
}

// buildDSN constructs the PostgreSQL connection string
func buildDSN() string {
	host := viper.GetString("DB_HOST")
	port := viper.GetString("DB_PORT")
	user := viper.GetString("DB_USER")
	password := viper.GetString("DB_PASSWORD")
	dbName := viper.GetString("DB_NAME")
	sslMode := viper.GetString("DB_SSLMODE")

	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbName, sslMode,
	)
}

// CloseDB closes the database connection gracefully
func CloseDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("❌ failed to get database instance: %w", err)
	}
	return sqlDB.Close()
}
```

### Step 2: Environment Variable Loading in Main

**File: `services/user-service/cmd/main.go`** (partial)

```go
package main

import (
	"log"

	"github.com/spf13/viper"
	"github.com/yourusername/microservices/pkg/config"
	"github.com/yourusername/microservices/services/user-service/internal/database"
)

func init() {
	// Load .env file
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("⚠️  Error reading .env file: %v", err)
	}
	viper.AutomaticEnv()
}

func main() {
	// Load configuration
	appConfig, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	log.Printf("🚀 Starting User Service on port %s", appConfig.Port)

	// Initialize database
	db, err := database.InitializeDB()
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.CloseDB(db)

	// Continue with service setup...
}
```

---

## 📦 Migrations (Production-Ready) {#migrations}

### Step 1: Create Migration Files

**File: `services/user-service/internal/database/migrations/001_create_users_table.sql`**

```sql
-- Create users table migration
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
```

**File: `services/user-service/internal/database/migrations/002_create_profiles_table.sql`**

```sql
-- Create user profiles table
CREATE TABLE IF NOT EXISTS user_profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
    avatar_url TEXT,
    bio TEXT,
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON user_profiles(user_id);
```

### Step 2: GORM Auto-Migration Setup

**File: `services/user-service/internal/database/migration.go`**

```go
package database

import (
	"fmt"
	"log"

	"gorm.io/gorm"
	"github.com/yourusername/microservices/services/user-service/internal/model"
)

// MigrateDB runs all database migrations
func MigrateDB(db *gorm.DB) error {
	log.Println("🔄 Running database migrations...")

	// Auto-migrate your models
	// This creates/updates tables based on struct tags
	err := db.AutoMigrate(
		&model.User{},
		&model.UserProfile{},
	)

	if err != nil {
		return fmt.Errorf("❌ migration failed: %w", err)
	}

	log.Println("✅ Migrations completed successfully")
	return nil
}

// DropDB drops all tables (use with caution!)
func DropDB(db *gorm.DB) error {
	log.Println("⚠️  WARNING: Dropping all database tables...")

	return db.Migrator().DropTable(
		&model.User{},
		&model.UserProfile{},
	)
}

// ResetDB drops and recreates all tables
func ResetDB(db *gorm.DB) error {
	if err := DropDB(db); err != nil {
		return err
	}
	return MigrateDB(db)
}
```

### Step 3: CLI Command for Manual Migrations

**File: `services/user-service/cmd/migrate/main.go`**

```go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/spf13/viper"
	"github.com/yourusername/microservices/pkg/config"
	"github.com/yourusername/microservices/services/user-service/internal/database"
)

func init() {
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("⚠️  Error reading .env file: %v", err)
	}
	viper.AutomaticEnv()
}

func main() {
	// Define CLI flags
	migrateFlag := flag.String("action", "migrate", "Action: migrate, rollback, reset, status")
	flag.Parse()

	// Load configuration
	appConfig, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.InitializeDB()
	if err != nil {
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.CloseDB(db)

	// Execute action
	switch *migrateFlag {
	case "migrate":
		if err := database.MigrateDB(db); err != nil {
			log.Fatalf("❌ Migration failed: %v", err)
		}
		fmt.Println("✅ Migration completed")

	case "reset":
		if err := database.ResetDB(db); err != nil {
			log.Fatalf("❌ Reset failed: %v", err)
		}
		fmt.Println("✅ Database reset completed")

	case "status":
		fmt.Println("📊 Database Status: OK")

	default:
		log.Fatalf("❌ Unknown action: %s", *migrateFlag)
	}
}
```

### Step 4: Makefile for Easy Commands

**File: `services/user-service/Makefile`**

```makefile
.PHONY: migrate migrate-rollback migrate-reset migrate-status build run test

# Run migrations
migrate:
	@echo "🔄 Running migrations..."
	@go run cmd/migrate/main.go -action=migrate

# Reset database (drop and recreate)
migrate-reset:
	@echo "⚠️  Resetting database..."
	@go run cmd/migrate/main.go -action=reset

# Check migration status
migrate-status:
	@echo "📊 Checking migration status..."
	@go run cmd/migrate/main.go -action=status

# Build the service
build:
	@echo "🔨 Building user-service..."
	@go build -o bin/user-service cmd/main.go

# Run the service
run: migrate
	@echo "🚀 Starting user-service..."
	@go run cmd/main.go

# Run tests
test:
	@echo "🧪 Running tests..."
	@go test ./...

# Run service with hot reload (requires `air`)
dev:
	@echo "🔄 Running with hot reload..."
	@air
```

---

## 🗄️ Models & Repository Layer {#models--repository}

### Step 1: Define Models

**File: `services/user-service/internal/model/user.go`**

```go
package model

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Email     string         `gorm:"unique;not null" json:"email"`
	Password  string         `gorm:"not null" json:"-"` // Never expose password in JSON
	FirstName string         `json:"first_name,omitempty"`
	LastName  string         `json:"last_name,omitempty"`
	IsActive  bool           `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"` // Soft delete

	// Relationships
	Profile *UserProfile `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"profile,omitempty"`
}

// UserProfile represents extended user information
type UserProfile struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	UserID      uint      `gorm:"uniqueIndex;not null" json:"user_id"`
	AvatarURL   string    `json:"avatar_url,omitempty"`
	Bio         string    `json:"bio,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"-"`
}

// CreateUserRequest is the DTO for creating a user
type CreateUserRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// UpdateUserRequest is the DTO for updating a user
type UpdateUserRequest struct {
	Email     string `json:"email,omitempty" binding:"omitempty,email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	IsActive  *bool  `json:"is_active,omitempty"`
}
```

### Step 2: Create Repository Layer

**File: `services/user-service/internal/repository/user_repository.go`**

```go
package repository

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"github.com/yourusername/microservices/services/user-service/internal/model"
)

// UserRepository defines all user-related database operations
type UserRepository interface {
	// Create operations
	Create(user *model.User) error

	// Read operations
	GetByID(id uint) (*model.User, error)
	GetByEmail(email string) (*model.User, error)
	GetAll(limit, offset int) ([]model.User, error)

	// Update operations
	Update(id uint, updates *model.UpdateUserRequest) error
	UpdatePassword(id uint, newPassword string) error

	// Delete operations
	Delete(id uint) error
	HardDelete(id uint) error

	// Utility operations
	Exists(email string) (bool, error)
	Count() (int64, error)
}

// userRepositoryImpl implements UserRepository interface
type userRepositoryImpl struct {
	db *gorm.DB
}

// NewUserRepository creates a new instance of UserRepository
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepositoryImpl{db: db}
}

// ============ CREATE OPERATIONS ============

// Create inserts a new user into the database
func (r *userRepositoryImpl) Create(user *model.User) error {
	if err := r.db.Create(user).Error; err != nil {
		return fmt.Errorf("❌ failed to create user: %w", err)
	}
	return nil
}

// ============ READ OPERATIONS ============

// GetByID retrieves a user by their ID
func (r *userRepositoryImpl) GetByID(id uint) (*model.User, error) {
	user := &model.User{}

	// Preload relationships (profile)
	if err := r.db.
		Preload("Profile").
		Where("id = ?", id).
		First(user).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("❌ user not found with ID: %d", id)
		}
		return nil, fmt.Errorf("❌ failed to fetch user: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by their email address
func (r *userRepositoryImpl) GetByEmail(email string) (*model.User, error) {
	user := &model.User{}

	if err := r.db.
		Preload("Profile").
		Where("email = ?", email).
		First(user).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("❌ user not found with email: %s", email)
		}
		return nil, fmt.Errorf("❌ failed to fetch user: %w", err)
	}

	return user, nil
}

// GetAll retrieves all users with pagination
func (r *userRepositoryImpl) GetAll(limit, offset int) ([]model.User, error) {
	var users []model.User

	// Default pagination values
	if limit == 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100 // Max limit
	}

	if err := r.db.
		Preload("Profile").
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {

		return nil, fmt.Errorf("❌ failed to fetch users: %w", err)
	}

	return users, nil
}

// ============ UPDATE OPERATIONS ============

// Update modifies an existing user's information
func (r *userRepositoryImpl) Update(id uint, updates *model.UpdateUserRequest) error {
	// Build dynamic update query
	updateData := map[string]interface{}{}

	if updates.Email != "" {
		updateData["email"] = updates.Email
	}
	if updates.FirstName != "" {
		updateData["first_name"] = updates.FirstName
	}
	if updates.LastName != "" {
		updateData["last_name"] = updates.LastName
	}
	if updates.IsActive != nil {
		updateData["is_active"] = *updates.IsActive
	}

	if err := r.db.Model(&model.User{}).Where("id = ?", id).Updates(updateData).Error; err != nil {
		return fmt.Errorf("❌ failed to update user: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password
func (r *userRepositoryImpl) UpdatePassword(id uint, newPassword string) error {
	if err := r.db.Model(&model.User{}).Where("id = ?", id).Update("password", newPassword).Error; err != nil {
		return fmt.Errorf("❌ failed to update password: %w", err)
	}
	return nil
}

// ============ DELETE OPERATIONS ============

// Delete performs a soft delete (marks as deleted)
func (r *userRepositoryImpl) Delete(id uint) error {
	if err := r.db.Where("id = ?", id).Delete(&model.User{}).Error; err != nil {
		return fmt.Errorf("❌ failed to delete user: %w", err)
	}
	return nil
}

// HardDelete permanently removes a user from the database
func (r *userRepositoryImpl) HardDelete(id uint) error {
	if err := r.db.Unscoped().Where("id = ?", id).Delete(&model.User{}).Error; err != nil {
		return fmt.Errorf("❌ failed to hard delete user: %w", err)
	}
	return nil
}

// ============ UTILITY OPERATIONS ============

// Exists checks if a user with the given email exists
func (r *userRepositoryImpl) Exists(email string) (bool, error) {
	var count int64

	if err := r.db.Model(&model.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("❌ failed to check user existence: %w", err)
	}

	return count > 0, nil
}

// Count returns the total number of active users
func (r *userRepositoryImpl) Count() (int64, error) {
	var count int64

	if err := r.db.Model(&model.User{}).Where("is_active = ?", true).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("❌ failed to count users: %w", err)
	}

	return count, nil
}
```

---

## 🔧 CRUD Operations & Service Layer {#crud-operations}

### Step 1: Create Service Layer

**File: `services/user-service/internal/service/user_service.go`**

```go
package service

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
	"github.com/yourusername/microservices/services/user-service/internal/model"
	"github.com/yourusername/microservices/services/user-service/internal/repository"
)

// UserService defines business logic for users
type UserService interface {
	// Create
	RegisterUser(req *model.CreateUserRequest) (*model.User, error)

	// Read
	GetUser(id uint) (*model.User, error)
	GetUserByEmail(email string) (*model.User, error)
	ListUsers(limit, offset int) ([]model.User, error)

	// Update
	UpdateUser(id uint, updates *model.UpdateUserRequest) (*model.User, error)
	ChangePassword(id uint, oldPassword, newPassword string) error

	// Delete
	DeactivateUser(id uint) error
	DeleteUser(id uint) error

	// Utility
	GetTotalUsers() (int64, error)
}

// userServiceImpl implements UserService
type userServiceImpl struct {
	repo repository.UserRepository
}

// NewUserService creates a new UserService instance
func NewUserService(repo repository.UserRepository) UserService {
	return &userServiceImpl{repo: repo}
}

// ============ CREATE OPERATIONS ============

// RegisterUser creates a new user with hashed password
func (s *userServiceImpl) RegisterUser(req *model.CreateUserRequest) (*model.User, error) {
	// Check if user already exists
	exists, err := s.repo.Exists(req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("❌ user with email %s already exists", req.Email)
	}

	// Hash password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("❌ failed to hash password: %w", err)
	}

	// Create user
	user := &model.User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
	}

	if err := s.repo.Create(user); err != nil {
		return nil, err
	}

	log.Printf("✅ User registered: %s", user.Email)
	return user, nil
}

// ============ READ OPERATIONS ============

// GetUser retrieves a user by ID
func (s *userServiceImpl) GetUser(id uint) (*model.User, error) {
	return s.repo.GetByID(id)
}

// GetUserByEmail retrieves a user by email
func (s *userServiceImpl) GetUserByEmail(email string) (*model.User, error) {
	return s.repo.GetByEmail(email)
}

// ListUsers retrieves all users with pagination
func (s *userServiceImpl) ListUsers(limit, offset int) ([]model.User, error) {
	return s.repo.GetAll(limit, offset)
}

// ============ UPDATE OPERATIONS ============

// UpdateUser updates a user's information
func (s *userServiceImpl) UpdateUser(id uint, updates *model.UpdateUserRequest) (*model.User, error) {
	// Verify user exists
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Update user
	if err := s.repo.Update(id, updates); err != nil {
		return nil, err
	}

	// Fetch updated user
	return s.repo.GetByID(id)
}

// ChangePassword securely changes a user's password
func (s *userServiceImpl) ChangePassword(id uint, oldPassword, newPassword string) error {
	user, err := s.repo.GetByID(id)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return fmt.Errorf("❌ invalid current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("❌ failed to hash new password: %w", err)
	}

	// Update password in repository
	return s.repo.UpdatePassword(id, string(hashedPassword))
}

// ============ DELETE OPERATIONS ============

// DeactivateUser soft-deletes a user (sets is_active to false)
func (s *userServiceImpl) DeactivateUser(id uint) error {
	updates := &model.UpdateUserRequest{
		IsActive: func(b bool) *bool { return &b }(false),
	}
	_, err := s.UpdateUser(id, updates)
	return err
}

// DeleteUser permanently removes a user
func (s *userServiceImpl) DeleteUser(id uint) error {
	return s.repo.HardDelete(id)
}

// ============ UTILITY OPERATIONS ============

// GetTotalUsers returns the total count of active users
func (s *userServiceImpl) GetTotalUsers() (int64, error) {
	return s.repo.Count()
}
```

---

## 🎯 Controllers & Routes {#controllers--routes}

### Step 1: Create Controller

**File: `services/user-service/internal/controller/user_controller.go`**

```go
package controller

import (
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/yourusername/microservices/services/user-service/internal/model"
	"github.com/yourusername/microservices/services/user-service/internal/service"
)

// UserController handles HTTP requests for user operations
type UserController struct {
	service service.UserService
}

// NewUserController creates a new UserController instance
func NewUserController(svc service.UserService) *UserController {
	return &UserController{service: svc}
}

// ============ CREATE ENDPOINTS ============

// Register handles user registration
// POST /users/register
func (c *UserController) Register(ctx *fiber.Ctx) error {
	var req model.CreateUserRequest

	// Parse request body
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Register user
	user, err := c.service.RegisterUser(&req)
	if err != nil {
		return ctx.Status(http.StatusConflict).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "user registered successfully",
		"data":    user,
	})
}

// ============ READ ENDPOINTS ============

// GetUser retrieves a user by ID
// GET /users/:id
func (c *UserController) GetUser(ctx *fiber.Ctx) error {
	// Extract user ID from URL parameter
	id, err := strconv.ParseUint(ctx.Params("id"), 10, 32)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	// Fetch user
	user, err := c.service.GetUser(uint(id))
	if err != nil {
		return ctx.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"data": user,
	})
}

// ListUsers retrieves all users with pagination
// GET /users?limit=10&offset=0
func (c *UserController) ListUsers(ctx *fiber.Ctx) error {
	// Parse query parameters
	limit, _ := strconv.Atoi(ctx.Query("limit", "10"))
	offset, _ := strconv.Atoi(ctx.Query("offset", "0"))

	// Validate pagination
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Fetch users
	users, err := c.service.ListUsers(limit, offset)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Get total count
	total, _ := c.service.GetTotalUsers()

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"data":  users,
		"total": total,
		"limit": limit,
		"offset": offset,
	})
}

// ============ UPDATE ENDPOINTS ============

// UpdateUser updates user information
// PUT /users/:id
func (c *UserController) UpdateUser(ctx *fiber.Ctx) error {
	// Extract user ID
	id, err := strconv.ParseUint(ctx.Params("id"), 10, 32)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	var req model.UpdateUserRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Update user
	user, err := c.service.UpdateUser(uint(id), &req)
	if err != nil {
		return ctx.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user updated successfully",
		"data":    user,
	})
}

// ChangePassword updates a user's password
// POST /users/:id/change-password
func (c *UserController) ChangePassword(ctx *fiber.Ctx) error {
	id, err := strconv.ParseUint(ctx.Params("id"), 10, 32)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Change password
	if err := c.service.ChangePassword(uint(id), req.OldPassword, req.NewPassword); err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"message": "password changed successfully",
	})
}

// ============ DELETE ENDPOINTS ============

// DeactivateUser deactivates a user account
// DELETE /users/:id/deactivate
func (c *UserController) DeactivateUser(ctx *fiber.Ctx) error {
	id, err := strconv.ParseUint(ctx.Params("id"), 10, 32)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	if err := c.service.DeactivateUser(uint(id)); err != nil {
		return ctx.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user deactivated successfully",
	})
}

// DeleteUser permanently removes a user
// DELETE /users/:id
func (c *UserController) DeleteUser(ctx *fiber.Ctx) error {
	id, err := strconv.ParseUint(ctx.Params("id"), 10, 32)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid user ID",
		})
	}

	if err := c.service.DeleteUser(uint(id)); err != nil {
		return ctx.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user deleted successfully",
	})
}
```

### Step 2: Define Routes

**File: `services/user-service/internal/routes/user_routes.go`**

```go
package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/yourusername/microservices/services/user-service/internal/controller"
)

// SetupUserRoutes configures all user-related routes
func SetupUserRoutes(app *fiber.App, controller *controller.UserController) {
	// Create a user group
	users := app.Group("/users")

	// ============ CREATE ============
	users.Post("/register", controller.Register)

	// ============ READ ============
	users.Get("", controller.ListUsers)               // List all users
	users.Get("/:id", controller.GetUser)              // Get single user

	// ============ UPDATE ============
	users.Put("/:id", controller.UpdateUser)           // Update user info
	users.Post("/:id/change-password", controller.ChangePassword)

	// ============ DELETE ============
	users.Delete("/:id/deactivate", controller.DeactivateUser)
	users.Delete("/:id", controller.DeleteUser)

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
}
```

### Step 3: Update Main to Wire Everything

**File: `services/user-service/cmd/main.go`** (complete)

```go
package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/spf13/viper"
	"github.com/yourusername/microservices/pkg/config"
	"github.com/yourusername/microservices/pkg/logger"
	"github.com/yourusername/microservices/services/user-service/internal/controller"
	"github.com/yourusername/microservices/services/user-service/internal/database"
	"github.com/yourusername/microservices/services/user-service/internal/repository"
	"github.com/yourusername/microservices/services/user-service/internal/routes"
	"github.com/yourusername/microservices/services/user-service/internal/service"
)

func init() {
	// Load environment variables
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("⚠️  Error reading .env file: %v", err)
	}
	viper.AutomaticEnv()
}

func main() {
	// Initialize logger
	appLogger := logger.New()

	// Load configuration
	appConfig, err := config.LoadConfig(".env")
	if err != nil {
		appLogger.Errorf("Failed to load config: %v", err)
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	appLogger.Infof("🚀 Starting User Service on port %s", appConfig.Port)

	// Initialize database connection
	db, err := database.InitializeDB()
	if err != nil {
		appLogger.Errorf("Failed to initialize database: %v", err)
		log.Fatalf("❌ Failed to initialize database: %v", err)
	}
	defer database.CloseDB(db)

	// Run migrations automatically
	if err := database.MigrateDB(db); err != nil {
		appLogger.Errorf("Failed to run migrations: %v", err)
		log.Fatalf("❌ Migration failed: %v", err)
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "User Service v1.0",
	})

	// Middleware
	app.Use(cors.New())

	// Initialize repository layer
	userRepo := repository.NewUserRepository(db)

	// Initialize service layer
	userService := service.NewUserService(userRepo)

	// Initialize controller layer
	userController := controller.NewUserController(userService)

	// Setup routes
	routes.SetupUserRoutes(app, userController)

	// Start server
	appLogger.Infof("✅ User Service listening on port %s", appConfig.Port)
	if err := app.Listen(":" + appConfig.Port); err != nil {
		appLogger.Errorf("Server error: %v", err)
	}
}
```

---

## 🚪 API Gateway Integration {#api-gateway}

### Step 1: API Gateway Structure

**File: `gateway/cmd/main.go`**

```go
package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/spf13/viper"
	"github.com/yourusername/microservices/gateway/internal/routes"
)

func init() {
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("⚠️  Error reading .env file: %v", err)
	}
	viper.AutomaticEnv()
}

func main() {
	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "API Gateway v1.0",
		Prefork: false,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Content-Type,Authorization",
	}))

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "gateway running", "service": "api-gateway"})
	})

	// Setup routes with service proxies
	routes.SetupGatewayRoutes(app)

	// Start gateway
	port := viper.GetString("GATEWAY_PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("🚪 API Gateway listening on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("❌ Gateway error: %v", err)
	}
}
```

### Step 2: Gateway Routes with Proxy

**File: `gateway/internal/routes/router.go`**

```go
package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
)

// ServiceConfig defines a microservice configuration
type ServiceConfig struct {
	Name string
	URL  string
}

// Services map holds all microservices
var Services = map[string]ServiceConfig{
	"user": {
		Name: "User Service",
		URL:  "http://localhost:3001",
	},
	"auth": {
		Name: "Auth Service",
		URL:  "http://localhost:3002",
	},
	"payment": {
		Name: "Payment Service",
		URL:  "http://localhost:3003",
	},
	"notification": {
		Name: "Notification Service",
		URL:  "http://localhost:3004",
	},
}

// SetupGatewayRoutes configures all API gateway routes
func SetupGatewayRoutes(app *fiber.App) {
	// ============ USER SERVICE ROUTES ============
	userGroup := app.Group("/api/v1/users")

	// Register user
	userGroup.Post("/register", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users/register")(c)
	})

	// List users
	userGroup.Get("/", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users")(c)
	})

	// Get user by ID
	userGroup.Get("/:id", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users/" + c.Params("id"))(c)
	})

	// Update user
	userGroup.Put("/:id", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users/" + c.Params("id"))(c)
	})

	// Change password
	userGroup.Post("/:id/change-password", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users/" + c.Params("id") + "/change-password")(c)
	})

	// Delete user
	userGroup.Delete("/:id", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["user"].URL + "/users/" + c.Params("id"))(c)
	})

	// ============ AUTH SERVICE ROUTES ============
	authGroup := app.Group("/api/v1/auth")

	// Login
	authGroup.Post("/login", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["auth"].URL + "/auth/login")(c)
	})

	// Logout
	authGroup.Post("/logout", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["auth"].URL + "/auth/logout")(c)
	})

	// Refresh token
	authGroup.Post("/refresh", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["auth"].URL + "/auth/refresh")(c)
	})

	// ============ PAYMENT SERVICE ROUTES ============
	paymentGroup := app.Group("/api/v1/payments")

	// Create payment
	paymentGroup.Post("/", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["payment"].URL + "/payments")(c)
	})

	// Get payment
	paymentGroup.Get("/:id", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["payment"].URL + "/payments/" + c.Params("id"))(c)
	})

	// ============ NOTIFICATION SERVICE ROUTES ============
	notifGroup := app.Group("/api/v1/notifications")

	// Send notification
	notifGroup.Post("/", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["notification"].URL + "/notifications")(c)
	})

	// Get notifications
	notifGroup.Get("/:userID", func(c *fiber.Ctx) error {
		return proxy.Forward(Services["notification"].URL + "/notifications/" + c.Params("userID"))(c)
	})
}
```

### Step 3: Gateway .env

**File: `gateway/.env`**

```bash
# Gateway Configuration
GATEWAY_PORT=8000
ENVIRONMENT=development

# Service URLs
USER_SERVICE_URL=http://localhost:3001
AUTH_SERVICE_URL=http://localhost:3002
PAYMENT_SERVICE_URL=http://localhost:3003
NOTIFICATION_SERVICE_URL=http://localhost:3004
```

### Step 4: Docker Compose for Local Development

**File: `docker-compose.yml`**

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: microservices_postgres
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - microservices_network

  # User Service
  user-service:
    build:
      context: ./services/user-service
      dockerfile: Dockerfile
    container_name: user_service
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_USER: postgres
      DB_PASSWORD: postgres
      DB_NAME: user_service_db
      DB_SSLMODE: disable
      PORT: 3001
    ports:
      - "3001:3001"
    depends_on:
      - postgres
    networks:
      - microservices_network

  # Auth Service
  auth-service:
    build:
      context: ./services/auth-service
      dockerfile: Dockerfile
    container_name: auth_service
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_USER: postgres
      DB_PASSWORD: postgres
      DB_NAME: auth_service_db
      DB_SSLMODE: disable
      PORT: 3002
    ports:
      - "3002:3002"
    depends_on:
      - postgres
    networks:
      - microservices_network

  # API Gateway
  gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile
    container_name: api_gateway
    environment:
      GATEWAY_PORT: 8000
      ENVIRONMENT: development
    ports:
      - "8000:8000"
    depends_on:
      - user-service
      - auth-service
    networks:
      - microservices_network

volumes:
  postgres_data:

networks:
  microservices_network:
    driver: bridge
```

---

## 🚀 Advanced: Transactions & Performance {#advanced-topics}

### Step 1: GORM Transactions Example

**File: `services/user-service/internal/service/user_service.go`** (additional methods)

```go
package service

import (
	"fmt"

	"gorm.io/gorm"
	"github.com/yourusername/microservices/services/user-service/internal/model"
	"github.com/yourusername/microservices/services/user-service/internal/repository"
)

// RegisterUserWithProfile registers a user and creates their profile in a transaction
func (s *userServiceImpl) RegisterUserWithProfile(
	req *model.CreateUserRequest,
	profile *model.UserProfile,
) (*model.User, error) {
	// This would require a transactional repository
	// For now, showing the concept:

	user, err := s.RegisterUser(req)
	if err != nil {
		return nil, err
	}

	// If profile creation fails, the user should be rolled back
	// This requires transaction support in the repository
	profile.UserID = user.ID

	return user, nil
}

// ============ TRANSACTIONAL REPOSITORY ENHANCEMENT ============

// TransactionalUserRepository extends UserRepository with transaction support
type TransactionalUserRepository interface {
	UserRepository
	// WithTx returns a new repository instance bound to a transaction
	WithTx(tx *gorm.DB) TransactionalUserRepository
}

// transactionalUserRepositoryImpl implements TransactionalUserRepository
type transactionalUserRepositoryImpl struct {
	userRepositoryImpl
}

// WithTx creates a new repository instance with the given transaction
func (r *transactionalUserRepositoryImpl) WithTx(tx *gorm.DB) TransactionalUserRepository {
	return &transactionalUserRepositoryImpl{
		userRepositoryImpl: userRepositoryImpl{db: tx},
	}
}
```

### Step 2: Service Layer with Transactions

**File: `services/user-service/internal/service/transaction_service.go`** (new file)

```go
package service

import (
	"fmt"

	"gorm.io/gorm"
	"github.com/yourusername/microservices/services/user-service/internal/model"
	"github.com/yourusername/microservices/services/user-service/internal/repository"
)

// TransactionService handles complex multi-step operations
type TransactionService interface {
	// RegisterUserWithProfile creates user and profile in a single transaction
	RegisterUserWithProfile(
		req *model.CreateUserRequest,
		profileData map[string]string,
	) (*model.User, error)

	// BulkUpdateUsers updates multiple users atomically
	BulkUpdateUsers(updates map[uint]*model.UpdateUserRequest) error
}

type transactionServiceImpl struct {
	db       *gorm.DB
	userRepo repository.UserRepository
}

// NewTransactionService creates a new TransactionService instance
func NewTransactionService(db *gorm.DB, userRepo repository.UserRepository) TransactionService {
	return &transactionServiceImpl{
		db:       db,
		userRepo: userRepo,
	}
}

// RegisterUserWithProfile creates a user and profile atomically
func (s *transactionServiceImpl) RegisterUserWithProfile(
	req *model.CreateUserRequest,
	profileData map[string]string,
) (*model.User, error) {
	var user *model.User

	// Start a transaction
	err := s.db.WithContext(s.db.Statement.Context).Transaction(func(tx *gorm.DB) error {
		// Step 1: Create user
		newUser := &model.User{
			Email:     req.Email,
			FirstName: req.FirstName,
			LastName:  req.LastName,
			IsActive:  true,
		}

		if err := tx.Create(newUser).Error; err != nil {
			return fmt.Errorf("❌ failed to create user: %w", err)
		}

		// Step 2: Create profile
		profile := &model.UserProfile{
			UserID:      newUser.ID,
			AvatarURL:   profileData["avatar_url"],
			Bio:         profileData["bio"],
			PhoneNumber: profileData["phone_number"],
		}

		if err := tx.Create(profile).Error; err != nil {
			// Rollback will happen automatically
			return fmt.Errorf("❌ failed to create profile: %w", err)
		}

		user = newUser
		return nil
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

// BulkUpdateUsers updates multiple users atomically
func (s *transactionServiceImpl) BulkUpdateUsers(updates map[uint]*model.UpdateUserRequest) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for userID, updateReq := range updates {
			updateData := map[string]interface{}{}

			if updateReq.Email != "" {
				updateData["email"] = updateReq.Email
			}
			if updateReq.FirstName != "" {
				updateData["first_name"] = updateReq.FirstName
			}
			if updateReq.IsActive != nil {
				updateData["is_active"] = *updateReq.IsActive
			}

			if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(updateData).Error; err != nil {
				return fmt.Errorf("❌ failed to update user %d: %w", userID, err)
			}
		}
		return nil
	}).Error
}
```

### Step 3: Connection Pooling Configuration

**File: `services/user-service/internal/database/connection.go`** (enhanced)

```go
package database

import (
	"time"

	"gorm.io/gorm"
)

// PoolConfig defines connection pool settings
type PoolConfig struct {
	MaxOpenConns    int           // Maximum number of open connections
	MaxIdleConns    int           // Maximum number of idle connections
	ConnMaxLifetime time.Duration // Maximum lifetime of a connection
	ConnMaxIdleTime time.Duration // Maximum idle time for a connection
}

// GetOptimalPoolConfig returns recommended pool settings for production
func GetOptimalPoolConfig(environment string) PoolConfig {
	switch environment {
	case "production":
		return PoolConfig{
			MaxOpenConns:    50,
			MaxIdleConns:    10,
			ConnMaxLifetime: 10 * time.Minute,
			ConnMaxIdleTime: 2 * time.Minute,
		}
	case "development":
		return PoolConfig{
			MaxOpenConns:    10,
			MaxIdleConns:    3,
			ConnMaxLifetime: 5 * time.Minute,
			ConnMaxIdleTime: 1 * time.Minute,
		}
	case "testing":
		return PoolConfig{
			MaxOpenConns:    5,
			MaxIdleConns:    1,
			ConnMaxLifetime: 1 * time.Minute,
			ConnMaxIdleTime: 30 * time.Second,
		}
	default:
		return PoolConfig{
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			ConnMaxIdleTime: 1 * time.Minute,
		}
	}
}

// InitializeDBWithPooling initializes GORM with optimized connection pooling
func InitializeDBWithPooling(environment string) (*gorm.DB, error) {
	db, err := InitializeDB()
	if err != nil {
		return nil, err
	}

	poolConfig := GetOptimalPoolConfig(environment)
	sqlDB, _ := db.DB()

	sqlDB.SetMaxOpenConns(poolConfig.MaxOpenConns)
	sqlDB.SetMaxIdleConns(poolConfig.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(poolConfig.ConnMaxLifetime)

	return db, nil
}
```

### Step 4: Query Optimization & Indexing

**File: `services/user-service/internal/repository/user_repository.go`** (optimized queries)

```go
package repository

import (
	"gorm.io/gorm"
	"github.com/yourusername/microservices/services/user-service/internal/model"
)

// QueryOptimizations provides optimized query methods

// GetActiveUsers retrieves only active users with efficient query
func (r *userRepositoryImpl) GetActiveUsers(limit, offset int) ([]model.User, error) {
	var users []model.User

	// Use SELECT to fetch only needed columns
	err := r.db.
		Select("id", "email", "first_name", "last_name", "created_at").
		Where("is_active = ?", true).
		Preload("Profile", func(db *gorm.DB) *gorm.DB {
			return db.Select("id", "user_id", "avatar_url", "bio")
		}).
		Limit(limit).
		Offset(offset).
		Find(&users).Error

	return users, err
}

// SearchUsers performs efficient full-text search
func (r *userRepositoryImpl) SearchUsers(query string) ([]model.User, error) {
	var users []model.User

	// Using indexes for faster search
	err := r.db.
		Where("email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
			"%"+query+"%", "%"+query+"%", "%"+query+"%").
		Find(&users).Error

	return users, err
}

// GetUserWithStats retrieves user with statistics using efficient queries
func (r *userRepositoryImpl) GetUserWithStats(id uint) (map[string]interface{}, error) {
	var result map[string]interface{}

	// Aggregate query
	err := r.db.
		Table("users").
		Where("id = ?", id).
		Select("id", "email", "first_name", "last_name", "created_at").
		First(&result).Error

	return result, err
}
```

---

## 📚 Best Practices Summary {#best-practices}

### 🎯 Core Microservice Architecture Principles

| Principle | Implementation | Why |
|-----------|----------------|-----|
| **Database per Service** | Each service owns its database (separate PostgreSQL instances) | Ensures loose coupling and independent scaling |
| **No Shared Database** | Services communicate via API, not shared DB | Prevents tight coupling and distributed transaction issues |
| **Service Isolation** | Complete database isolation | Services can scale independently and fail independently |
| **Environment Separation** | Dev, staging, production databases | Prevents accidental data loss and enables safe testing |

---

### 🔐 Environment & Configuration Best Practices

```go
// ✅ DO: Load config from environment
config, _ := config.LoadConfig(".env")

// ❌ DON'T: Hardcode database credentials
// const DBPassword = "postgres"

// ✅ DO: Validate required configuration on startup
if err := validateConfig(config); err != nil {
    log.Fatal("Missing critical config")
}

// ✅ DO: Use .env for local development only
// Production: use secret management (Vault, AWS Secrets Manager)
```

---

### 🗄️ Migration Best Practices

```go
// ✅ DO: Version your migrations with timestamps
// Filenames: 001_create_users_table.sql, 002_add_email_index.sql

// ✅ DO: Run migrations automatically on service startup
func main() {
    db, _ := database.InitializeDB()
    database.MigrateDB(db)  // Auto-migrate before server starts
}

// ✅ DO: Make migrations idempotent (safe to run multiple times)
CREATE TABLE IF NOT EXISTS users (...)
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)

// ❌ DON'T: Create tables without IF NOT EXISTS
// ❌ DON'T: Run migrations manually in production

// ✅ DO: Keep rollback scripts ready for emergencies
func RollbackMigration(db *gorm.DB) error {
    return db.Migrator().DropTable(&User{})
}
```

---

### 🏗️ Repository & Service Layer Best Practices

```go
// ✅ DO: Separate concerns into layers
// Repository: Database access logic only
// Service: Business logic
// Controller: HTTP handling

// ✅ DO: Use interfaces for dependency injection
type UserRepository interface {
    Create(user *User) error
    GetByID(id uint) (*User, error)
}

// ✅ DO: Return wrapped errors with context
if err != nil {
    return fmt.Errorf("❌ failed to create user: %w", err)
}

// ❌ DON'T: Expose database errors directly to API
// ❌ DON'T: Mix business logic in repositories
```

---

### 🔄 CRUD Operation Best Practices

```go
// ✅ DO: Validate input before database operations
if exists, _ := repo.Exists(email); exists {
    return fmt.Errorf("user already exists")
}

// ✅ DO: Use transactions for multi-step operations
db.Transaction(func(tx *gorm.DB) error {
    // Step 1: Create user
    // Step 2: Create profile
    // Either both succeed or both fail
    return nil
})

// ✅ DO: Use soft deletes for user data (GDPR compliance)
type User struct {
    DeletedAt gorm.DeletedAt
}

// ✅ DO: Hash passwords before storing
hashedPwd, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// ❌ DON'T: Store plain text passwords
// ❌ DON'T: Mix business logic with repository queries
```

---

### 🔌 Connection Pooling Best Practices

```go
// ✅ DO: Configure connection pools based on workload
// Production: MaxOpenConns = 50, MaxIdleConns = 10
// Development: MaxOpenConns = 10, MaxIdleConns = 3

sqlDB.SetMaxOpenConns(25)
sqlDB.SetMaxIdleConns(5)
sqlDB.SetConnMaxLifetime(5 * time.Minute)

// ✅ DO: Monitor connection pool metrics
// Use: SHOW max_connections; on PostgreSQL

// ✅ DO: Test connection on startup
sqlDB.Ping()

// ❌ DON'T: Use default connection pool settings
// ❌ DON'T: Open new connections for each query
```

---

### 🌐 API Gateway Best Practices

```go
// ✅ DO: Route requests to correct service
GET /api/v1/users → http://localhost:3001/users

// ✅ DO: Implement request/response logging
app.Use(middleware.Logger())

// ✅ DO: Add rate limiting at gateway level
app.Use(ratelimit.New())

// ✅ DO: Implement circuit breaker for service failures
// If auth-service is down, fail fast instead of waiting

// ✅ DO: Add request correlation IDs for tracing
c.Set("x-correlation-id", uuid.New().String())

// ❌ DON'T: Couple gateway to service logic
// ❌ DON'T: Run complex business logic in gateway
```

---

### ⚡ Performance Optimization Best Practices

```go
// ✅ DO: Use indexes on frequently queried columns
CREATE INDEX idx_users_email ON users(email);

// ✅ DO: Preload relationships efficiently
db.Preload("Profile").Find(&users)  // Eager loading

// ✅ DO: Select only needed columns
db.Select("id", "email", "first_name").Find(&users)

// ✅ DO: Paginate large result sets
db.Limit(10).Offset(0).Find(&users)

// ✅ DO: Use database connection pooling
sqlDB.SetMaxOpenConns(50)

// ❌ DON'T: N+1 queries (query user, then for each user query profile)
for _, user := range users {
    db.Find(&user.Profile)  // ❌ This runs in a loop!
}

// ✅ DO: Batch operations instead
db.Preload("Profile").Find(&users)  // ✅ Single query with join
```

---

### 🔒 Security Best Practices

```go
// ✅ DO: Validate all inputs
type CreateUserRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
}

// ✅ DO: Hash sensitive data
bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// ✅ DO: Use HTTPS in production
// ✅ DO: Implement authentication middleware
// ✅ DO: Add request rate limiting
// ✅ DO: Validate database connections use SSL

// ❌ DON'T: Expose password fields in API responses
type User struct {
    Password string `json:"-"` // Omitted from JSON
}

// ❌ DON'T: Store config in code
// ❌ DON'T: Use default database passwords
```

---

### 📊 Monitoring & Logging Best Practices

```go
// ✅ DO: Log service startup/shutdown
logger.Infof("✅ User Service started on port %s", port)

// ✅ DO: Log important operations
logger.Infof("User registered: %s", user.Email)

// ✅ DO: Log errors with context
logger.Errorf("Failed to create user: %v", err)

// ✅ DO: Monitor database connections
// Track: connections_open, connections_idle, query_time

// ✅ DO: Use structured logging for easy parsing
type LogEntry struct {
    Timestamp string
    Level     string
    Message   string
    Error     string
}

// ❌ DON'T: Log sensitive data (passwords, tokens)
// ❌ DON'T: Use println for production logging
```

---

### 🧪 Testing Best Practices

```go
// ✅ DO: Create separate test database
const testDBName = "user_service_test_db"

// ✅ DO: Reset database before each test
func setup(t *testing.T) *gorm.DB {
    db := setupTestDB()
    db.Migrator().DropTable(&User{})
    db.AutoMigrate(&User{})
    return db
}

// ✅ DO: Test repository layer with real database
func TestCreateUser(t *testing.T) {
    repo := NewUserRepository(testDB)
    err := repo.Create(&User{Email: "test@example.com"})
    assert.NoError(t, err)
}

// ✅ DO: Mock external services
type MockUserRepository struct {}
func (m *MockUserRepository) GetByID(id uint) (*User, error) {
    return &User{ID: id}, nil
}
```

---

### 🚀 Deployment Best Practices

```bash
# ✅ DO: Use Docker for containerization
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o main cmd/main.go
FROM alpine:latest
COPY --from=builder /app/main .
CMD ["./main"]

# ✅ DO: Use Docker Compose for local development
docker-compose up -d

# ✅ DO: Health checks
GET /health → {"status": "ok"}

# ✅ DO: Graceful shutdown
signal.Notify(sigChan, os.Interrupt)
<-sigChan
database.CloseDB(db)

# ❌ DON'T: Run services without containers
# ❌ DON'T: Hardcode service URLs (use environment variables)
```

---

## 📝 Quick Reference Checklist

```markdown
## Pre-Deployment Checklist

- [ ] Environment variables configured
- [ ] Database migrations tested
- [ ] Connection pooling optimized
- [ ] Error handling implemented
- [ ] Logging configured
- [ ] API routes documented
- [ ] Rate limiting configured
- [ ] CORS properly set
- [ ] Health checks working
- [ ] Tests passing
- [ ] Docker image building successfully
- [ ] Database backups configured
- [ ] Monitoring alerts set up
- [ ] Documentation complete
- [ ] Code reviewed
```

---

## 🔗 Complete Repository Structure Reference

```
microservices/
├── gateway/
│   ├── cmd/
│   │   └── main.go                    # Gateway entry point
│   ├── internal/
│   │   ├── routes/
│   │   │   └── router.go              # Route definitions
│   │   └── proxy/
│   │       └── handler.go             # Proxy handlers
│   ├── .env
│   ├── go.mod
│   ├── Dockerfile
│   └── Makefile
│
├── services/
│   ├── user-service/
│   │   ├── cmd/
│   │   │   ├── main.go                # Service entry point
│   │   │   └── migrate/
│   │   │       └── main.go            # Migration CLI
│   │   ├── internal/
│   │   │   ├── controller/
│   │   │   │   └── user_controller.go # HTTP handlers
│   │   │   ├── model/
│   │   │   │   └── user.go            # Data models & DTOs
│   │   │   ├── repository/
│   │   │   │   └── user_repository.go # Database access
│   │   │   ├── service/
│   │   │   │   ├── user_service.go    # Business logic
│   │   │   │   └── transaction_service.go
│   │   │   ├── database/
│   │   │   │   ├── connection.go      # DB connection
│   │   │   │   └── migration.go       # Migration logic
│   │   │   └── routes/
│   │   │       └── user_routes.go     # Route definitions
│   │   ├── .env
│   │   ├── go.mod
│   │   ├── Dockerfile
│   │   └── Makefile
│   │
│   ├── auth-service/
│   ├── payment-service/
│   └── notification-service/
│
├── pkg/
│   ├── config/
│   │   └── config.go                  # Shared configuration
│   ├── logger/
│   │   └── logger.go                  # Logging utilities
│   └── middleware/
│       └── cors.go                    # Middleware utilities
│
├── docker-compose.yml                 # Local development setup
└── README.md
```

---

## 🎓 Summary

This guide covers **production-ready GORM microservices** with:

✅ **Structured Architecture**: Clear separation of concerns (controller → service → repository → database)
✅ **Environment Management**: Viper & dotenv configuration  
✅ **Database Migrations**: Automated and manual migration options  
✅ **CRUD Operations**: Full-featured repository and service layers  
✅ **Transaction Support**: Multi-step atomic operations  
✅ **Connection Pooling**: Optimized for production performance  
✅ **API Gateway**: Request routing and service orchestration  
✅ **Security**: Password hashing, input validation, error handling  
✅ **Best Practices**: Scalability, maintainability, and reliability  

You now have a complete, enterprise-grade blueprint for building microservices in Go! 🚀
