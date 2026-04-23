# Contributing to BFDS FalconEye

Thank you for your interest in contributing to BFDS FalconEye — Bank Fraud Detection System!

## 🤝 How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please:
1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Environment details (OS, Python version, SQL Server version)

### Pull Requests

We welcome contributions! To submit a pull request:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation as needed
   - Test your changes thoroughly

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit a Pull Request**
   - Describe your changes clearly
   - Reference related issues
   - Ensure all tests pass

## 📝 Development Guidelines

### Code Style

- **Python**: Follow PEP 8 guidelines
- **SQL**: Use consistent formatting, add comments for complex queries
- **HTML/JavaScript**: Follow existing patterns in bfdsUI

### Database Changes

When modifying SQL scripts:
1. Update the script version number in filename
2. Add comments explaining the change
3. Test in development environment first
4. Update relevant documentation

### API Changes

When modifying the Flask API:
1. Update `bfds_api/app.py`
2. Test endpoints with Postman or curl
3. Update `bfds_api/README.md` if API changes
4. Increment version in `requirements.txt` if dependencies change

### UI Changes

When modifying the web interface:
1. Update HTML/CSS/JavaScript in bfdsUI
2. Test in multiple browsers (Chrome, Firefox, Edge)
3. Ensure responsive design is maintained
4. Update README if new features are added

## 🧪 Testing

- Test database changes with `TestCaseQuery.sql`
- Test API endpoints with Postman or curl
- Test UI in multiple browsers
- Verify role-based access control

## 📋 Project Structure

```
DataBaseProject/
├── bfds_api/                 # Flask REST API
│   ├── app.py               # Main API application
│   ├── requirements.txt     # Python dependencies
│   └── README.md            # API documentation
├── bfdsUI/                   # Web Interface
│   ├── login.html           # Authentication page
│   └── app.html             # Main dashboard
└── SQL Scripts/             # Database setup
```

## 🎯 Areas for Contribution

We're particularly interested in contributions for:
- **Machine learning fraud detection** models
- **Additional fraud detection rules**
- **UI/UX improvements**
- **Documentation enhancements**
- **Performance optimizations**
- **Security improvements**

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## 📞 Contact

For questions about contributing, please contact the LSUS Database Development Team.

---

Thank you for contributing to BFDS FalconEye!
