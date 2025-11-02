GROM implemnetation
# 🚀 GORM Migration & Implementation Guide

## 📋 Table of Contents
1. [Introduction](#introduction)
2. [Setup & Installation](#setup--installation)
3. [Database Models](#database-models)
4. [Auto Migration](#auto-migration)
5. [Manual Migration](#manual-migration)
6. [Complete Implementation Example](#complete-implementation-example)
7. [Advanced Migration Techniques](#advanced-migration-techniques)

---

## Introduction

**GORM** (Go Object-Relational Mapping) is a powerful ORM library for Go that provides:
- Auto migrations
- Associations (Has One, Has Many, Many to Many)
- Hooks (Before/After Create/Update/Delete)
- Preloading (Eager loading)
- Transactions

---

## Setup & Installation

### 1️⃣ Install Dependencies

```bash
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres  # or mysql, sqlite, sqlserver
```

### 2️⃣ Project Structure

```
project/
├── main.go
├── models/
│   ├── user.go
│   ├── product.go
│   └── order.go
├── database/
│   └── connection.go
└── migrations/
    └── migrate.go
```

---

## Database Models

### 📦 User Model

```go
// models/user.go
package models

import (
    "time"
    "gorm.io/gorm"
)

type User struct {
    ID        uint           `gorm:"primaryKey"`
    CreatedAt time.Time
    UpdatedAt time.Time
    DeletedAt gorm.DeletedAt `gorm:"index"`
    
    Name      string         `gorm:"size:100;not null"`
    Email     string         `gorm:"uniqueIndex;not null"`
    Age       int            `gorm:"default:18"`
    Active    bool           `gorm:"default:true"`
    
    // Relationships
    Profile   Profile        `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
    Orders    []Order        `gorm:"foreignKey:UserID"`
}

// Hooks
func (u *User) BeforeCreate(tx *gorm.DB) error {
    // Custom logic before creating user
    if u.Email == "" {
        return errors.New("email is required")
    }
    return nil
}
```

### 📦 Profile Model

```go
// models/profile.go
package models

import "gorm.io/gorm"

type Profile struct {
    gorm.Model
    UserID   uint   `gorm:"uniqueIndex;not null"`
    Bio      string `gorm:"type:text"`
    Avatar   string `gorm:"size:255"`
    Address  string `gorm:"size:500"`
}
```

### 📦 Product & Order Models

```go
// models/product.go
package models

import "gorm.io/gorm"

type Product struct {
    gorm.Model
    Name        string  `gorm:"size:200;not null"`
    Description string  `gorm:"type:text"`
    Price       float64 `gorm:"type:decimal(10,2);not null"`
    Stock       int     `gorm:"default:0"`
    
    // Many-to-Many relationship
    Orders      []Order `gorm:"many2many:order_products;"`
}
```

```go
// models/order.go
package models

import (
    "time"
    "gorm.io/gorm"
)

type Order struct {
    gorm.Model
    UserID      uint      `gorm:"not null;index"`
    OrderDate   time.Time `gorm:"default:CURRENT_TIMESTAMP"`
    TotalAmount float64   `gorm:"type:decimal(10,2)"`
    Status      string    `gorm:"size:50;default:'pending'"`
    
    // Relationships
    User        User      `gorm:"foreignKey:UserID"`
    Products    []Product `gorm:"many2many:order_products;"`
}
```

---

## Auto Migration

### 🔄 Basic Auto Migration

```go
// database/connection.go
package database

import (
    "fmt"
    "log"
    
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    
    "yourapp/models"
)

var DB *gorm.DB

func Connect() {
    dsn := "host=localhost user=postgres password=postgres dbname=gorm_demo port=5432 sslmode=disable"
    
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
        Logger: logger.Default.LogMode(logger.Info),
    })
    
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    
    DB = db
    fmt.Println("✅ Database connected successfully!")
}

func Migrate() {
    err := DB.AutoMigrate(
        &models.User{},
        &models.Profile{},
        &models.Product{},
        &models.Order{},
    )
    
    if err != nil {
        log.Fatal("Migration failed:", err)
    }
    
    fmt.Println("✅ Database migration completed!")
}
```

---

## Manual Migration

### 🛠️ Custom Migration with Migrator

```go
// migrations/migrate.go
package migrations

import (
    "fmt"
    "gorm.io/gorm"
    "yourapp/models"
)

func RunMigrations(db *gorm.DB) error {
    migrator := db.Migrator()
    
    // Check if table exists
    if !migrator.HasTable(&models.User{}) {
        fmt.Println("Creating users table...")
        if err := migrator.CreateTable(&models.User{}); err != nil {
            return err
        }
    }
    
    // Add column if doesn't exist
    if !migrator.HasColumn(&models.User{}, "LastLogin") {
        fmt.Println("Adding LastLogin column...")
        if err := migrator.AddColumn(&models.User{}, "LastLogin"); err != nil {
            return err
        }
    }
    
    // Create index
    if !migrator.HasIndex(&models.User{}, "idx_user_email") {
        fmt.Println("Creating email index...")
        if err := db.Exec("CREATE INDEX idx_user_email ON users(email)").Error; err != nil {
            return err
        }
    }
    
    // Modify column type
    if err := migrator.AlterColumn(&models.User{}, "Name"); err != nil {
        return err
    }
    
    return nil
}

// Rollback specific table
func RollbackUsers(db *gorm.DB) error {
    return db.Migrator().DropTable(&models.User{})
}
```

---

## Complete Implementation Example

### 🎯 Main Application

```go
// main.go
package main

import (
    "fmt"
    "log"
    "time"
    
    "yourapp/database"
    "yourapp/models"
)

func main() {
    // Connect to database
    database.Connect()
    
    // Run migrations
    database.Migrate()
    
    // Seed data
    seedData()
    
    // CRUD operations
    performCRUD()
}

func seedData() {
    // Create Users
    users := []models.User{
        {Name: "Alice Johnson", Email: "alice@example.com", Age: 28},
        {Name: "Bob Smith", Email: "bob@example.com", Age: 35},
        {Name: "Charlie Brown", Email: "charlie@example.com", Age: 42},
    }
    
    for _, user := range users {
        result := database.DB.Create(&user)
        if result.Error != nil {
            log.Printf("Error creating user: %v", result.Error)
            continue
        }
        fmt.Printf("✅ Created user: %s (ID: %d)\n", user.Name, user.ID)
        
        // Create Profile
        profile := models.Profile{
            UserID:  user.ID,
            Bio:     fmt.Sprintf("Bio for %s", user.Name),
            Avatar:  fmt.Sprintf("avatar_%d.jpg", user.ID),
            Address: fmt.Sprintf("%d Main St", user.ID*100),
        }
        database.DB.Create(&profile)
    }
    
    // Create Products
    products := []models.Product{
        {Name: "Laptop", Description: "High-performance laptop", Price: 1299.99, Stock: 50},
        {Name: "Mouse", Description: "Wireless mouse", Price: 29.99, Stock: 200},
        {Name: "Keyboard", Description: "Mechanical keyboard", Price: 89.99, Stock: 100},
    }
    
    for _, product := range products {
        database.DB.Create(&product)
        fmt.Printf("✅ Created product: %s\n", product.Name)
    }
}

func performCRUD() {
    fmt.Println("\n🔍 CRUD Operations\n")
    
    // CREATE
    createUser()
    
    // READ
    readUsers()
    
    // UPDATE
    updateUser()
    
    // DELETE
    deleteUser()
    
    // Associations
    createOrderWithProducts()
    
    // Query with preload
    queryWithPreload()
}

func createUser() {
    user := models.User{
        Name:  "Diana Prince",
        Email: "diana@example.com",
        Age:   30,
    }
    
    result := database.DB.Create(&user)
    fmt.Printf("➕ Created user with ID: %d (Rows affected: %d)\n", user.ID, result.RowsAffected)
}

func readUsers() {
    // Find all
    var users []models.User
    database.DB.Find(&users)
    
    fmt.Println("\n📋 All Users:")
    for _, user := range users {
        fmt.Printf("  - %s (%s) - Age: %d\n", user.Name, user.Email, user.Age)
    }
    
    // Find by ID
    var user models.User
    database.DB.First(&user, 1) // Find user with ID 1
    fmt.Printf("\n🔎 User with ID 1: %s\n", user.Name)
    
    // Find with conditions
    var adults []models.User
    database.DB.Where("age > ?", 30).Find(&adults)
    fmt.Printf("\n👥 Users older than 30: %d\n", len(adults))
}

func updateUser() {
    var user models.User
    database.DB.First(&user, 1)
    
    // Update single field
    database.DB.Model(&user).Update("Age", 29)
    
    // Update multiple fields
    database.DB.Model(&user).Updates(models.User{Name: "Alice J.", Age: 30})
    
    // Update with map
    database.DB.Model(&user).Updates(map[string]interface{}{
        "Active": true,
        "Age":    31,
    })
    
    fmt.Printf("✏️  Updated user: %s\n", user.Name)
}

func deleteUser() {
    var user models.User
    database.DB.Where("email = ?", "diana@example.com").First(&user)
    
    // Soft delete (if DeletedAt field exists)
    database.DB.Delete(&user)
    fmt.Printf("🗑️  Soft deleted user: %s\n", user.Name)
    
    // Permanent delete
    // database.DB.Unscoped().Delete(&user)
}

func createOrderWithProducts() {
    var user models.User
    var products []models.Product
    
    database.DB.First(&user, 1)
    database.DB.Limit(2).Find(&products)
    
    order := models.Order{
        UserID:      user.ID,
        OrderDate:   time.Now(),
        TotalAmount: 1329.98,
        Status:      "pending",
        Products:    products,
    }
    
    database.DB.Create(&order)
    fmt.Printf("🛒 Created order #%d for %s with %d products\n", order.ID, user.Name, len(products))
}

func queryWithPreload() {
    var orders []models.Order
    
    // Preload relationships
    database.DB.Preload("User").Preload("Products").Find(&orders)
    
    fmt.Println("\n📦 Orders with Preloaded Data:")
    for _, order := range orders {
        fmt.Printf("  Order #%d - User: %s - Products: %d - Total: $%.2f\n",
            order.ID, order.User.Name, len(order.Products), order.TotalAmount)
    }
}
```

---

## Advanced Migration Techniques

### 🔧 Versioned Migrations

```go
// migrations/versions.go
package migrations

import (
    "fmt"
    "gorm.io/gorm"
)

type Migration struct {
    Version int
    Name    string
    Up      func(*gorm.DB) error
    Down    func(*gorm.DB) error
}

var migrations = []Migration{
    {
        Version: 1,
        Name:    "create_users_table",
        Up: func(db *gorm.DB) error {
            return db.Exec(`
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `).Error
        },
        Down: func(db *gorm.DB) error {
            return db.Exec("DROP TABLE users").Error
        },
    },
    {
        Version: 2,
        Name:    "add_age_to_users",
        Up: func(db *gorm.DB) error {
            return db.Exec("ALTER TABLE users ADD COLUMN age INTEGER DEFAULT 18").Error
        },
        Down: func(db *gorm.DB) error {
            return db.Exec("ALTER TABLE users DROP COLUMN age").Error
        },
    },
}

func RunVersionedMigrations(db *gorm.DB) error {
    for _, m := range migrations {
        fmt.Printf("Running migration %d: %s\n", m.Version, m.Name)
        if err := m.Up(db); err != nil {
            return fmt.Errorf("migration %d failed: %w", m.Version, err)
        }
    }
    return nil
}
```

### 🎯 Migration with Seeds

```go
// migrations/seed.go
package migrations

import (
    "gorm.io/gorm"
    "yourapp/models"
)

func SeedDatabase(db *gorm.DB) error {
    // Create admin user
    admin := models.User{
        Name:   "Admin User",
        Email:  "admin@example.com",
        Age:    35,
        Active: true,
    }
    
    if err := db.FirstOrCreate(&admin, models.User{Email: admin.Email}).Error; err != nil {
        return err
    }
    
    // Create sample products
    products := []models.Product{
        {Name: "Product A", Price: 99.99, Stock: 100},
        {Name: "Product B", Price: 149.99, Stock: 50},
    }
    
    for _, p := range products {
        db.FirstOrCreate(&p, models.Product{Name: p.Name})
    }
    
    return nil
}
```

---

## 📊 Summary Table

| Feature | Command/Method | Description |
|---------|---------------|-------------|
| **Auto Migrate** | `db.AutoMigrate(&Model{})` | Automatically creates/updates tables |
| **Create Table** | `db.Migrator().CreateTable(&Model{})` | Manually create table |
| **Drop Table** | `db.Migrator().DropTable(&Model{})` | Delete table |
| **Add Column** | `db.Migrator().AddColumn(&Model{}, "field")` | Add new column |
| **Drop Column** | `db.Migrator().DropColumn(&Model{}, "field")` | Remove column |
| **Has Table** | `db.Migrator().HasTable(&Model{})` | Check if table exists |
| **Rename Table** | `db.Migrator().RenameTable(&Old{}, &New{})` | Rename table |

---

## 🎓 Best Practices

> **✅ DO:**
> - Use `gorm.Model` for standard fields (ID, CreatedAt, UpdatedAt, DeletedAt)
> - Define indexes on frequently queried columns
> - Use migrations in development, not in production directly
> - Version your migration files
> - Always test rollback procedures

> **❌ DON'T:**
> - Run AutoMigrate in production without testing
> - Forget to handle errors in migrations
> - Mix ORM queries with raw SQL unnecessarily
> - Ignore database constraints

---

## 🚀 Running the Application

```bash
# Initialize module
go mod init yourapp

# Install dependencies
go mod tidy

# Run application
go run main.go
```

**Output:**
```
✅ Database connected successfully!
✅ Database migration completed!
✅ Created user: Alice Johnson (ID: 1)
✅ Created user: Bob Smith (ID: 2)
✅ Created product: Laptop
🛒 Created order #1 for Alice Johnson with 2 products
```

---

**🎉 You now have a complete GORM migration and implementation setup!** This example covers auto-migration, manual migrations, CRUD operations, relationships, and advanced techniques. Adapt it to your specific database and requirements.
