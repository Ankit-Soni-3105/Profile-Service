# LinkedIn Complete Microservices Production Architecture

## 🏗 Root Project Structure

linkedin-microservices/
├── infrastructure/
├── services/ (25 microservices)
├── shared-libraries/
├── deployment/
├── monitoring/
└── ci-cd/


## 📦 All 25 Microservices Complete Structure

### 1. Profile Creation & Setup Service

profile-creation-service/
├── src/
│   ├── controllers/
│   │   ├── ProfileCreationController.js
│   │   ├── EmailVerificationController.js
│   │   ├── PhoneVerificationController.js
│   │   ├── WelcomeTourController.js
│   │   ├── AccountActivationController.js
│   │   ├── TemplateController.js
│   │   ├── ImportController.js
│   │   ├── SocialLinkingController.js
│   │   ├── ProgressController.js
│   │   └── DuplicatePreventionController.js
│   ├── services/
│   │   ├── VerificationService.js
│   │   ├── WizardService.js
│   │   ├── TemplateService.js
│   │   ├── ImportService.js
│   │   ├── SocialService.js
│   │   ├── ProgressService.js
│   │   └── DuplicateService.js
│   ├── models/
│   │   ├── ProfileSetup.js
│   │   ├── Verification.js
│   │   ├── Progress.js
│   │   └── Template.js
│   ├── routes/
│   │   ├── setup.routes.js
│   │   ├── verification.routes.js
│   │   └── progress.routes.js
│   └── utils/
│       ├── emailHelper.js
│       └── smsHelper.js
├── database/migrations/
│   ├── 001_profile_setup.sql
│   └── 002_verifications.sql
├── tests/
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
└── package.json

API: POST /api/v1/setup/create, POST /api/v1/setup/verify-email
DB: profile_setup, verifications tables


### 2. Personal Information Service

personal-info-service/
├── src/
│   ├── controllers/
│   │   ├── PersonalInfoController.js
│   │   ├── ContactController.js
│   │   ├── LocationController.js
│   │   ├── TimezoneController.js
│   │   ├── ProfileUrlController.js
│   │   ├── VanityUrlController.js
│   │   ├── WebsiteController.js
│   │   ├── SocialLinksController.js
│   │   └── UpdateHistoryController.js
│   ├── services/
│   │   ├── PersonalInfoService.js
│   │   ├── LocationService.js
│   │   ├── UrlService.js
│   │   ├── ValidationService.js
│   │   └── TimezoneService.js
│   ├── models/
│   │   ├── PersonalInfo.js
│   │   ├── ContactInfo.js
│   │   └── SocialLinks.js
│   └── routes/
│       └── personal.routes.js
├── database/migrations/
│   └── 001_personal_info.sql
├── k8s/
└── package.json

API: GET/PUT /api/v1/personal/:userId, POST /api/v1/personal/contact
DB: personal_info, contact_info tables


### 3. Profile Photo Service

profile-photo-service/
├── src/
│   ├── controllers/
│   │   ├── PhotoUploadController.js
│   │   ├── CroppingController.js
│   │   ├── OptimizationController.js
│   │   ├── BackgroundRemovalController.js
│   │   ├── QualityController.js
│   │   ├── VisibilityController.js
│   │   ├── HistoryController.js
│   │   ├── TempPhotoController.js
│   │   ├── AccessibilityController.js
│   │   └── DownloadController.js
│   ├── services/
│   │   ├── UploadService.js
│   │   ├── ImageProcessingService.js
│   │   ├── StorageService.js
│   │   ├── OptimizationService.js
│   │   └── AnalyticsService.js
│   ├── models/
│   │   ├── Photo.js
│   │   ├── PhotoHistory.js
│   │   └── PhotoSettings.js
│   └── routes/
│       └── photo.routes.js
├── database/migrations/
├── k8s/
└── package.json

API: POST /api/v1/photo/upload, PUT /api/v1/photo/crop, GET /api/v1/photo/:photoId
DB: photos, photo_history tables
Storage: AWS S3/Azure Blob


### 4. Background Cover Service

background-cover-service/
├── src/
│   ├── controllers/
│   │   ├── CoverUploadController.js
│   │   ├── TemplateController.js
│   │   ├── DesignController.js
│   │   ├── BrandingController.js
│   │   ├── SchedulingController.js
│   │   ├── ABTestController.js
│   │   └── AnalyticsController.js
│   ├── services/
│   │   ├── CoverService.js
│   │   ├── TemplateService.js
│   │   ├── DesignService.js
│   │   └── SchedulerService.js
│   ├── models/
│   │   ├── CoverPhoto.js
│   │   ├── Template.js
│   │   └── Design.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/cover/upload, GET /api/v1/cover/templates
DB: cover_photos, templates


### 5. Professional Headline Service

professional-headline-service/
├── src/
│   ├── controllers/
│   │   ├── HeadlineController.js
│   │   ├── SuggestionController.js
│   │   ├── OptimizationController.js
│   │   ├── ABTestController.js
│   │   ├── AnalyticsController.js
│   │   └── HistoryController.js
│   ├── services/
│   │   ├── HeadlineService.js
│   │   ├── SuggestionService.js
│   │   ├── OptimizationService.js
│   │   └── AnalyticsService.js
│   ├── models/
│   │   ├── Headline.js
│   │   ├── HeadlineTest.js
│   │   └── HeadlineHistory.js
│   └── routes/
├── k8s/
└── package.json

API: PUT /api/v1/headline/:userId, GET /api/v1/headline/suggestions
DB: headlines, headline_tests


### 6. About/Summary Service

about-summary-service/
├── src/
│   ├── controllers/
│   │   ├── SummaryController.js
│   │   ├── EditorController.js
│   │   ├── FormattingController.js
│   │   ├── SuggestionController.js
│   │   ├── GrammarController.js
│   │   ├── TemplateController.js
│   │   ├── TranslationController.js
│   │   ├── VoiceInputController.js
│   │   └── BackupController.js
│   ├── services/
│   │   ├── SummaryService.js
│   │   ├── GrammarService.js
│   │   ├── TemplateService.js
│   │   ├── TranslationService.js
│   │   └── BackupService.js
│   ├── models/
│   │   ├── Summary.js
│   │   ├── SummaryTemplate.js
│   │   └── SummaryBackup.js
│   └── routes/
├── k8s/
└── package.json

API: PUT /api/v1/summary/:userId, GET /api/v1/summary/templates
DB: summaries, templates, backups


### 7. Experience Management Service

experience-management-service/
├── src/
│   ├── controllers/
│   │   ├── ExperienceController.js
│   │   ├── CompanyController.js
│   │   ├── JobTitleController.js
│   │   ├── LocationController.js
│   │   ├── DurationController.js
│   │   ├── TemplateController.js
│   │   ├── AchievementController.js
│   │   ├── SkillTagController.js
│   │   ├── ProjectController.js
│   │   ├── MediaController.js
│   │   └── VerificationController.js
│   ├── services/
│   │   ├── ExperienceService.js
│   │   ├── CompanyService.js
│   │   ├── VerificationService.js
│   │   └── TemplateService.js
│   ├── models/
│   │   ├── Experience.js
│   │   ├── Company.js
│   │   ├── Achievement.js
│   │   └── Media.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/experience, PUT /api/v1/experience/:id
DB: experiences, companies, achievements


### 8. Education Service

education-service/
├── src/
│   ├── controllers/
│   │   ├── EducationController.js
│   │   ├── SchoolController.js
│   │   ├── DegreeController.js
│   │   ├── GradeController.js
│   │   ├── HonorsController.js
│   │   ├── ThesisController.js
│   │   ├── AdvisorController.js
│   │   ├── StudyAbroadController.js
│   │   ├── ProjectController.js
│   │   ├── CourseController.js
│   │   ├── OrganizationController.js
│   │   └── MediaController.js
│   ├── services/
│   │   ├── EducationService.js
│   │   ├── SchoolService.js
│   │   └── ValidationService.js
│   ├── models/
│   │   ├── Education.js
│   │   ├── School.js
│   │   ├── Course.js
│   │   └── Honor.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/education, GET /api/v1/education/:userId
DB: education, schools, courses


### 9. Skills Management Service

skills-management-service/
├── src/
│   ├── controllers/
│   │   ├── SkillController.js
│   │   ├── CategoryController.js
│   │   ├── ProficiencyController.js
│   │   ├── ExperienceController.js
│   │   ├── PriorityController.js
│   │   ├── SuggestionController.js
│   │   ├── TrendController.js
│   │   ├── AnalysisController.js   
│   │   ├── ComparisonController.js
│   │   ├── CertificationController.js
│   │   ├── SynonymController.js
│   │   └── DemandController.js
│   ├── services/
│   │   ├── SkillService.js
│   │   ├── CategoryService.js
│   │   ├── TrendService.js
│   │   ├── AnalysisService.js
│   │   └── SuggestionService.js
│   ├── models/
│   │   ├── Skill.js
│   │   ├── SkillCategory.js
│   │   ├── SkillTrend.js
│   │   └── SkillDemand.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/skills, GET /api/v1/skills/trends
DB: skills, skill_categories, trends


### 10. Endorsement Service

endorsement-service/
├── src/
│   ├── controllers/
│   │   ├── EndorsementController.js
│   │   ├── NotificationController.js
│   │   ├── MutualController.js
│   │   ├── QualityController.js
│   │   ├── FraudDetectionController.js
│   │   ├── AutomationController.js
│   │   ├── DisplayController.js
│   │   ├── AnalyticsController.js
│   │   ├── SuggestionController.js
│   │   ├── WeightController.js
│   │   ├── MilestoneController.js
│   │   └── ExportController.js
│   ├── services/
│   │   ├── EndorsementService.js
│   │   ├── NotificationService.js
│   │   ├── FraudDetectionService.js
│   │   ├── AnalyticsService.js
│   │   └── SuggestionService.js
│   ├── models/
│   │   ├── Endorsement.js
│   │   ├── EndorsementQuality.js
│   │   ├── EndorsementAnalytics.js
│   │   └── Milestone.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/endorsement, GET /api/v1/endorsement/analytics
DB: endorsements, quality_scores, analytics


### 11. Recommendation Service

recommendation-service/
├── src/
│   ├── controllers/
│   │   ├── RecommendationController.js
│   │   ├── RequestController.js
│   │   ├── TemplateController.js
│   │   ├── ReminderController.js
│   │   ├── DraftController.js
│   │   ├── ApprovalController.js
│   │   ├── DisplayController.js
│   │   ├── AnalyticsController.js
│   │   ├── SharingController.js
│   │   ├── ThankYouController.js
│   │   └── QualityController.js
│   ├── services/
│   │   ├── RecommendationService.js
│   │   ├── TemplateService.js
│   │   ├── ReminderService.js
│   │   ├── ApprovalService.js
│   │   └── QualityService.js
│   ├── models/
│   │   ├── Recommendation.js
│   │   ├── RecommendationRequest.js
│   │   ├── Draft.js
│   │   └── Quality.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/recommendation/request, PUT /api/v1/recommendation/:id
DB: recommendations, requests, drafts


### 12. Certification & License Service

certification-license-service/
├── src/
│   ├── controllers/
│   │   ├── CertificationController.js
│   │   ├── LicenseController.js
│   │   ├── OrganizationController.js
│   │   ├── VerificationController.js
│   │   ├── ExpirationController.js
│   │   ├── RenewalController.js
│   │   ├── BadgeController.js
│   │   ├── CategoryController.js
│   │   ├── EducationController.js
│   │   ├── SharingController.js
│   │   └── RecognitionController.js
│   ├── services/
│   │   ├── CertificationService.js
│   │   ├── VerificationService.js
│   │   ├── RenewalService.js
│   │   └── BadgeService.js
│   ├── models/
│   │   ├── Certification.js
│   │   ├── License.js
│   │   ├── Organization.js
│   │   └── Badge.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/certification, GET /api/v1/certification/expiring
DB: certifications, licenses, organizations


### 13. Language Service

language-service/
├── src/
│   ├── controllers/
│   │   ├── LanguageController.js
│   │   ├── ProficiencyController.js
│   │   ├── CertificationController.js
│   │   ├── AssessmentController.js
│   │   ├── NativeController.js
│   │   ├── ProgressController.js
│   │   ├── VersionController.js
│   │   ├── TestingController.js
│   │   ├── ContextController.js
│   │   ├── PairController.js
│   │   ├── TranslationController.js
│   │   └── TeachingController.js
│   ├── services/
│   │   ├── LanguageService.js
│   │   ├── ProficiencyService.js
│   │   ├── AssessmentService.js
│   │   └── TranslationService.js
│   ├── models/
│   │   ├── Language.js
│   │   ├── Proficiency.js
│   │   ├── Assessment.js
│   │   └── Translation.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/language, PUT /api/v1/language/proficiency
DB: languages, proficiencies, assessments


### 14. Volunteer Experience Service

volunteer-experience-service/
├── src/
│   ├── controllers/
│   │   ├── VolunteerController.js
│   │   ├── OrganizationController.js
│   │   ├── CauseController.js
│   │   ├── RoleController.js
│   │   ├── TimeController.js
│   │   ├── ImpactController.js
│   │   ├── SkillController.js
│   │   ├── ReferenceController.js
│   │   ├── CertificateController.js
│   │   ├── HoursController.js
│   │   ├── LeadershipController.js
│   │   ├── FundraisingController.js
│   │   └── StoryController.js
│   ├── services/
│   │   ├── VolunteerService.js
│   │   ├── OrganizationService.js
│   │   ├── ImpactService.js
│   │   └── TimeService.js
│   ├── models/
│   │   ├── Volunteer.js
│   │   ├── Organization.js
│   │   ├── Impact.js
│   │   └── Hours.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/volunteer, GET /api/v1/volunteer/impact
DB: volunteer_experience, organizations, impact


### 15. Projects Portfolio Service

projects-portfolio-service/
├── src/
│   ├── controllers/
│   │   ├── ProjectController.js
│   │   ├── TeamController.js
│   │   ├── TechnologyController.js
│   │   ├── CategoryController.js
│   │   ├── MediaController.js
│   │   ├── OutcomeController.js
│   │   ├── TestimonialController.js
│   │   ├── StatusController.js
│   │   ├── CollaborationController.js
│   │   ├── MethodologyController.js
│   │   ├── ResourceController.js
│   │   └── AwardController.js
│   ├── services/
│   │   ├── ProjectService.js
│   │   ├── TeamService.js
│   │   ├── MediaService.js
│   │   └── OutcomeService.js
│   ├── models/
│   │   ├── Project.js
│   │   ├── Team.js
│   │   ├── Technology.js
│   │   └── Media.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/project, GET /api/v1/project/:userId
DB: projects, teams, technologies, media


### 16. Publications Service

publications-service/
├── src/
│   ├── controllers/
│   │   ├── PublicationController.js
│   │   ├── TypeController.js
│   │   ├── AuthorController.js
│   │   ├── JournalController.js
│   │   ├── DOIController.js
│   │   ├── CitationController.js
│   │   ├── StatusController.js
│   │   ├── ReviewController.js
│   │   ├── KeywordController.js
│   │   ├── AbstractController.js
│   │   ├── DownloadController.js
│   │   ├── ImpactController.js
│   │   └── IndexingController.js
│   ├── services/
│   │   ├── PublicationService.js
│   │   ├── AuthorService.js
│   │   ├── CitationService.js
│   │   └── ImpactService.js
│   ├── models/
│   │   ├── Publication.js
│   │   ├── Author.js
│   │   ├── Journal.js
│   │   └── Citation.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/publication, GET /api/v1/publication/citations
DB: publications, authors, journals, citations


### 17. Patents Service

patents-service/
├── src/
│   ├── controllers/
│   │   ├── PatentController.js
│   │   ├── OfficeController.js
│   │   ├── FilingController.js
│   │   ├── GrantController.js
│   │   ├── StatusController.js
│   │   ├── InventorController.js
│   │   ├── ClassificationController.js
│   │   ├── PriorityController.js
│   │   ├── FamilyController.js
│   │   ├── LicensingController.js
│   │   ├── CitationController.js
│   │   └── ApplicationController.js
│   ├── services/
│   │   ├── PatentService.js
│   │   ├── StatusService.js
│   │   ├── InventorService.js
│   │   └── LicensingService.js
│   ├── models/
│   │   ├── Patent.js
│   │   ├── Inventor.js
│   │   ├── Classification.js
│   │   └── Licensing.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/patent, GET /api/v1/patent/status
DB: patents, inventors, classifications


### 18. Honors & Awards Service

honors-awards-service/
├── src/
│   ├── controllers/
│   │   ├── AwardController.js
│   │   ├── CategoryController.js
│   │   ├── OrganizationController.js
│   │   ├── CriteriaController.js
│   │   ├── RecognitionController.js
│   │   ├── ImageController.js
│   │   ├── NominationController.js
│   │   ├── ValueController.js
│   │   ├── MediaController.js
│   │   └── ImpactController.js
│   ├── services/
│   │   ├── AwardService.js
│   │   ├── CategoryService.js
│   │   ├── OrganizationService.js
│   │   └── ImpactService.js
│   ├── models/
│   │   ├── Award.js
│   │   ├── Category.js
│   │   ├── Organization.js
│   │   └── Media.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/award, GET /api/v1/award/:userId
DB: awards, categories, organizations


### 19. Test Scores Service

test-scores-service/
├── src/
│   ├── controllers/
│   │   ├── TestScoreController.js
│   │   ├── TestController.js
│   │   ├── ScoreController.js
│   │   ├── PercentileController.js
│   │   ├── ValidityController.js
│   │   ├── RetakeController.js
│   │   ├── ReportingController.js
│   │   ├── AnalysisController.js
│   │   ├── BenchmarkController.js
│   │   └── ImprovementController.js
│   ├── services/
│   │   ├── TestScoreService.js
│   │   ├── ScoreService.js
│   │   ├── AnalysisService.js
│   │   └── BenchmarkService.js
│   ├── models/
│   │   ├── TestScore.js
│   │   ├── Test.js
│   │   ├── Score.js
│   │   └── Benchmark.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/test-score, GET /api/v1/test-score/analysis
DB: test_scores, tests, benchmarks


### 20. Organizations Service

organizations-service/
├── src/
│   ├── controllers/
│   │   ├── OrganizationController.js
│   │   ├── TypeController.js
│   │   ├── MembershipController.js
│   │   ├── PositionController.js
│   │   ├── BenefitController.js
│   │   ├── ActivityController.js
│   │   ├── CommitteeController.js
│   │   ├── BoardController.js
│   │   ├── FeeController.js
│   │   └── DevelopmentController.js
│   ├── services/
│   │   ├── OrganizationService.js
│   │   ├── MembershipService.js
│   │   ├── ActivityService.js
│   │   └── DevelopmentService.js
│   ├── models/
│   │   ├── Organization.js
│   │   ├── Membership.js
│   │   ├── Position.js
│   │   └── Activity.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/organization, GET /api/v1/organization/membership
DB: organizations, memberships, activities


### 21. Profile Analytics Service

profile-analytics-service/
├── src/
│   ├── controllers/
│   │   ├── AnalyticsController.js
│   │   ├── ViewsController.js
│   │   ├── TrendsController.js
│   │   ├── DemographicsController.js
│   │   ├── SourceController.js
│   │   ├── GeographicController.js
│   │   ├── IndustryController.js
│   │   ├── CompletenessController.js
│   │   ├── RankingController.js
│   │   ├── StrengthController.js
│   │   ├── EngagementController.js
│   │   ├── ClickController.js
│   │   └── ExportController.js
│   ├── services/
│   │   ├── AnalyticsService.js
│   │   ├── ViewsService.js
│   │   ├── TrendsService.js
│   │   ├── DemographicsService.js
│   │   └── RankingService.js
│   ├── models/
│   │   ├── Analytics.js
│   │   ├── Views.js
│   │   ├── Demographics.js
│   │   └── Trends.js
│   └── routes/
├── k8s/
└── package.json

API: GET /api/v1/analytics/:userId, GET /api/v1/analytics/trends
DB: analytics, views, demographics, trends


### 22. Privacy & Security Service

privacy-security-service/
├── src/
│   ├── controllers/
│   │   ├── PrivacyController.js
│   │   ├── VisibilityController.js
│   │   ├── ConnectionController.js
│   │   ├── ActivityController.js
│   │   ├── SearchController.js
│   │   ├── AuthenticationController.js
│   │   ├── LoginController.js
│   │   ├── PasswordController.js
│   │   ├── DeactivationController.js
│   │   ├── DataController.js
│   │   ├── BlockingController.js
│   │   └── ReportingController.js
│   ├── services/
│   │   ├── PrivacyService.js
│   │   ├── SecurityService.js
│   │   ├── AuthService.js
│   │   ├── DataService.js
│   │   └── ReportingService.js
│   ├── models/
│   │   ├── Privacy.js
│   │   ├── Security.js
│   │   ├── Blocking.js
│   │   └── Report.js
│   └── routes/
├── k8s/
└── package.json

API: PUT /api/v1/privacy/settings, POST /api/v1/security/2fa
DB: privacy_settings, security_settings, blocks







### 12. Certification & License Service

certification-license-service/
├── src/
│   ├── controllers/
│   │   ├── CertificationController.js
│   │   ├── LicenseController.js
│   │   ├── OrganizationController.js
│   │   ├── VerificationController.js
│   │   ├── ExpirationController.js
│   │   ├── RenewalController.js
│   │   ├── BadgeController.js
│   │   ├── CategoryController.js
│   │   ├── EducationController.js
│   │   ├── SharingController.js
│   │   └── RecognitionController.js
│   ├── services/
│   │   ├── CertificationService.js
│   │   ├── VerificationService.js
│   │   ├── RenewalService.js
│   │   └── BadgeService.js
│   ├── models/
│   │   ├── Certification.js
│   │   ├── License.js
│   │   ├── Organization.js
│   │   └── Badge.js
│   └── routes/
├── k8s/
└── package.json

API: POST /api/v1/certification, GET /api/v1/certification/expiring
DB: certifications, licenses, organizations


iska Certification.js model do mujhe jo ki same to same mere is experience.model ki tarah hoga like =>import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';
import redis from 'redis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Initialize Redis client
const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.connect().catch(err => console.error('Redis connection error:', err));

// Validation Functions
const validateZipCode = (value) => !value || /^[0-9]{5}(-[0-9]{4})?$/.test(value);
const validateURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);
const validateJobTitle = (value) => /^[a-zA-Z0-9\s\-&()]+$/.test(value);

// Sub-Schemas
const locationSchema = new Schema({
    city: { type: String, trim: true, maxlength: 50, index: true },
    state: { type: String, trim: true, maxlength: 50 },
    country: { type: String, trim: true, maxlength: 50, index: true },
    zipCode: { type: String, trim: true, maxlength: 10, validate: { validator: validateZipCode, message: 'Invalid zip code format' } },
    timezone: { type: String, trim: true, maxlength: 50 },
    coordinates: { type: { type: String, enum: ['Point'], default: 'Point' }, coordinates: { type: [Number], index: '2dsphere' } },
    isRemote: { type: Boolean, default: false, index: true }
}, { _id: false });

const durationSchema = new Schema({
    startDate: { type: Date, required: [true, 'Start date is required'], index: true },
    endDate: { type: Date, index: true },
    isCurrent: { type: Boolean, default: false, index: true },
    expectedEndDate: { type: Date }
}, { _id: false });

const responsibilitySchema = new Schema({
    text: { type: String, maxlength: 500, required: true, validate: { validator: v => v && v.trim().length > 0, message: 'Responsibility text cannot be empty' } },
    category: { type: String, enum: ['leadership', 'technical', 'strategic', 'operational', 'creative', 'analytical', 'communication', 'project-management'] },
    impact: { type: String, maxlength: 200 },
    metrics: { type: String, maxlength: 200 },
    order: { type: Number, default: 0 },
    isHighlighted: { type: Boolean, default: false }
}, { _id: false });

const skillSchema = new Schema({
    name: { type: String, trim: true, maxlength: 50, required: true, validate: { validator: v => v && v.trim().length > 0, message: 'Skill name cannot be empty' } },
    category: { type: String, enum: ['technical', 'soft', 'language', 'certification', 'tool', 'framework'] },
    level: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'], default: 'intermediate' },
    yearsExperience: { type: Number, min: 0, max: 50 },
    endorsed: { type: Boolean, default: false },
    endorsementCount: { type: Number, default: 0, min: 0 },
    lastUsed: { type: Date },
    isCertified: { type: Boolean, default: false },
    certificationUrl: { type: String, validate: { validator: validateURL, message: 'Invalid certification URL' } }
}, { _id: false });

const achievementSchema = new Schema({
    title: { type: String, maxlength: 200 },
    description: { type: String, maxlength: 500 },
    type: { type: String, enum: ['award', 'certification', 'recognition', 'milestone', 'promotion', 'project-completion'] },
    dateAchieved: { type: Date },
    issuedBy: { type: String, maxlength: 100 },
    verificationUrl: { type: String, validate: { validator: validateURL, message: 'Invalid verification URL' } },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }],
    isPublic: { type: Boolean, default: true }
}, { _id: false });

const projectSchema = new Schema({
    name: { type: String, maxlength: 100 },
    description: { type: String, maxlength: 1000 },
    role: { type: String, maxlength: 100 },
    technologies: [{ type: String, maxlength: 50 }],
    startDate: { type: Date },
    endDate: { type: Date },
    url: { type: String, validate: { validator: validateURL, message: 'Invalid project URL' } },
    teamSize: { type: Number, min: 1 },
    budget: { type: Number, min: 0 },
    impact: { type: String, maxlength: 300 },
    isOngoing: { type: Boolean, default: false },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }]
}, { _id: false });

const endorsementSchema = new Schema({
    endorserId: { type: Schema.Types.ObjectId, ref: 'User' },
    endorserName: { type: String, maxlength: 100 },
    endorserTitle: { type: String, maxlength: 100 },
    endorserCompany: { type: String, maxlength: 100 },
    relationship: { type: String, enum: ['manager', 'direct-report', 'colleague', 'client', 'vendor', 'other'] },
    endorsedAt: { type: Date, default: Date.now },
    comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    rating: { type: Number, min: 1, max: 5 },
    skills: [{ type: String, maxlength: 50 }],
    isVerified: { type: Boolean, default: false },
    isPublic: { type: Boolean, default: true }
}, { _id: false });

const verificationSchema = new Schema({
    isVerified: { type: Boolean, default: false, index: true },
    verifiedBy: { type: Schema.Types.ObjectId },
    verificationDate: { type: Date },
    verificationMethod: { type: String, enum: ['email', 'hr-contact', 'document', 'colleague', 'certificate', 'linkedin-sync', 'background-check'] },
    verificationScore: { type: Number, min: 0, max: 100, default: 0 },
    documents: [{
        type: { type: String, enum: ['offer-letter', 'contract', 'certificate', 'pay-stub', 'id-card'] },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid document URL' } },
        uploadedAt: { type: Date, default: Date.now }
    }],
    hrContactEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid HR contact email' } },
    hrContactVerified: { type: Boolean, default: false }
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showDuration: { type: Boolean, default: true },
    showSalary: { type: Boolean, default: false },
    showResponsibilities: { type: Boolean, default: true },
    showEndorsements: { type: Boolean, default: true },
    visibleToConnections: { type: Boolean, default: true },
    visibleToRecruiters: { type: Boolean, default: true },
    visibleToColleagues: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    allowContactFromRecruiters: { type: Boolean, default: true }
}, { _id: false });

const salarySchema = new Schema({
    amount: { type: Number, min: 0 },
    currency: { type: String, maxlength: 3, default: 'USD' },
    period: { type: String, enum: ['hourly', 'monthly', 'yearly'], default: 'yearly' },
    isEstimate: { type: Boolean, default: false },
    benefits: [{ type: { type: String, enum: ['health', 'dental', 'vision', '401k', 'stock', 'bonus', 'vacation', 'remote', 'other'] }, value: { type: String, maxlength: 100 } }],
    equityPackage: { hasEquity: { type: Boolean, default: false }, type: { type: String, enum: ['stock-options', 'rsu', 'espp', 'warrants'] }, percentage: { type: Number, min: 0, max: 100 } }
}, { _id: false });

const performanceSchema = new Schema({
    rating: { type: Number, min: 1, max: 5 },
    feedback: { type: String, maxlength: 2000 },
    goals: [{ title: { type: String, maxlength: 200 }, status: { type: String, enum: ['not-started', 'in-progress', 'completed', 'exceeded'] }, deadline: { type: Date }, achievement: { type: String, maxlength: 500 } }],
    promotions: [{ fromTitle: { type: String, maxlength: 100 }, toTitle: { type: String, maxlength: 100 }, date: { type: Date }, salaryIncrease: { type: Number, min: 0 } }],
    awards: { type: Number, default: 0, min: 0 },
    recognitions: [{ type: String, maxlength: 200 }]
}, { _id: false });

const connectionsSchema = new Schema({
    colleagues: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, relationship: { type: String, enum: ['manager', 'direct-report', 'peer', 'cross-team'] }, connectedAt: { type: Date, default: Date.now } }],
    managers: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, startDate: { type: Date }, endDate: { type: Date } }],
    reports: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, startDate: { type: Date }, endDate: { type: Date } }],
    mentors: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, relationship: { type: String, enum: ['mentor', 'mentee', 'sponsor'] } }]
}, { _id: false });

const aiInsightsSchema = new Schema({
    skillGaps: [{ type: String, maxlength: 50 }],
    careerProgression: { type: String, maxlength: 200 },
    salaryPrediction: { type: Number, min: 0 },
    marketDemand: { type: String, enum: ['low', 'medium', 'high', 'very-high'] },
    similarRoles: [{ type: String, maxlength: 100 }],
    industryTrends: [{ type: String, maxlength: 100 }],
    recommendedSkills: [{ type: String, maxlength: 50 }],
    lastAnalyzed: { type: Date }
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['linkedin', 'indeed', 'manual', 'api', 'csv-import'] },
    importId: { type: String },
    templateId: { type: Schema.Types.ObjectId },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    duplicateOf: { type: Schema.Types.ObjectId },
    isDuplicate: { type: Boolean, default: false }
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: { type: Number, default: 0, min: 0 },
    contactRequests: { type: Number, default: 0, min: 0 },
    lastViewed: { type: Date },
    viewersCount: { type: Number, default: 0, min: 0 },
    shareCount: { type: Number, default: 0, min: 0 },
    likesCount: { type: Number, default: 0, min: 0 },
    commentsCount: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    clickThroughRate: { type: Number, default: 0, min: 0 },
    engagementScore: { type: Number, default: 0, min: 0 }
}, { _id: false });

const statusSchema = new Schema({
    isActive: { type: Boolean, default: true, index: true },
    isDeleted: { type: Boolean, default: false, index: true },
    isFeatured: { type: Boolean, default: false },
    isPromoted: { type: Boolean, default: false },
    isPremium: { type: Boolean, default: false },
    isSponsored: { type: Boolean, default: false },
    deletedAt: { type: Date },
    archivedAt: { type: Date },
    featuredUntil: { type: Date },
    lastActiveAt: { type: Date, default: Date.now },
    workflow: { type: String, enum: ['draft', 'pending-review', 'published', 'archived'], default: 'published' }
}, { _id: false });

const socialSchema = new Schema({
    likes: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, likedAt: { type: Date, default: Date.now } }],
    comments: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, comment: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }, commentedAt: { type: Date, default: Date.now }, isPublic: { type: Boolean, default: true } }],
    shares: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'internal'] }, sharedAt: { type: Date, default: Date.now } }],
    bookmarks: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, bookmarkedAt: { type: Date, default: Date.now } }]
}, { _id: false });

// Main Experience Schema
const experienceSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    companyId: { type: Schema.Types.ObjectId, ref: 'Company', required: [true, 'Company ID is required'], index: true },
    jobTitle: { type: String, required: [true, 'Job title is required'], trim: true, maxlength: 100, index: true, validate: { validator: validateJobTitle, message: 'Invalid job title format' } },
    department: { type: String, trim: true, maxlength: 50, index: true },
    employmentType: { type: String, enum: ['full-time', 'part-time', 'contract', 'internship', 'freelance', 'volunteer', 'apprenticeship', 'seasonal'], required: [true, 'Employment type is required'], index: true },
    workArrangement: { type: String, enum: ['on-site', 'remote', 'hybrid'], default: 'on-site', index: true },
    seniorityLevel: { type: String, enum: ['internship', 'entry-level', 'associate', 'mid-senior', 'senior', 'director', 'executive', 'c-level'], index: true },
    location: locationSchema,
    duration: durationSchema,
    description: { type: String, maxlength: 5000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    responsibilities: [responsibilitySchema],
    skills: [skillSchema],
    achievements: [achievementSchema],
    projects: [projectSchema],
    endorsements: [endorsementSchema],
    verification: verificationSchema,
    privacy: privacySchema,
    salary: salarySchema,
    performance: performanceSchema,
    connections: connectionsSchema,
    aiInsights: aiInsightsSchema,
    metadata: metadataSchema,
    analytics: analyticsSchema,
    social: socialSchema,
    cache: {
        searchVector: { type: String, index: 'text' },
        popularityScore: { type: Number, default: 0, index: true },
        trendingScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, {
    timestamps: true,
    collection: 'experiences',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.social.comments;
            delete ret.verification.documents;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw'
});

// Indexes
experienceSchema.index({ userId: 1, 'duration.startDate': -1, 'status.isActive': 1 });
experienceSchema.index({ companyId: 1, jobTitle: 1, 'status.isActive': 1 });
experienceSchema.index({ 'location.country': 1, 'location.city': 1, employmentType: 1 });
experienceSchema.index({ jobTitle: 1, seniorityLevel: 1, 'verification.isVerified': 1 });
experienceSchema.index({ 'skills.name': 1, seniorityLevel: 1, 'verification.isVerified': 1, 'privacy.searchable': 1 });
experienceSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
experienceSchema.index({ 'duration.isCurrent': 1, userId: 1, 'status.workflow': 1 });
experienceSchema.index({ 'aiInsights.marketDemand': 1, 'aiInsights.lastAnalyzed': -1 });
experienceSchema.index({ 'location.coordinates': '2dsphere' }, { sparse: true });
experienceSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
experienceSchema.index({
    jobTitle: 'text',
    description: 'text',
    department: 'text',
    'responsibilities.text': 'text',
    'skills.name': 'text',
    'projects.name': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { jobTitle: 10, 'skills.name': 8, department: 6, description: 4, 'responsibilities.text': 3, 'projects.name': 2, 'cache.searchVector': 1 },
    name: 'experience_text_search'
});
experienceSchema.index({ 'salary.amount': 1, 'salary.currency': 1, 'location.country': 1, seniorityLevel: 1 }, { sparse: true });
experienceSchema.index({ employmentType: 1, workArrangement: 1, 'location.isRemote': 1, 'duration.isCurrent': 1 });
experienceSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
experienceSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });

// Virtuals
experienceSchema.virtual('durationInMonths').get(function () {
    const endDate = this.duration.endDate || new Date();
    const startDate = this.duration.startDate;
    return Math.ceil(Math.abs(endDate - startDate) / (1000 * 60 * 60 * 24 * 30.44));
});
experienceSchema.virtual('durationInYears').get(function () {
    return Math.floor(this.durationInMonths / 12);
});
experienceSchema.virtual('durationFormatted').get(function () {
    const years = this.durationInYears;
    const months = this.durationInMonths % 12;
    if (years === 0) return `${months} month${months !== 1 ? 's' : ''}`;
    if (months === 0) return `${years} year${years !== 1 ? 's' : ''}`;
    return `${years} year${years !== 1 ? 's' : ''} ${months} month${months !== 1 ? 's' : ''}`;
});
experienceSchema.virtual('skillsCount').get(function () {
    return this.skills?.length || 0;
});
experienceSchema.virtual('endorsementCount').get(function () {
    return this.endorsements?.length || 0;
});
experienceSchema.virtual('achievementCount').get(function () {
    return this.achievements?.length || 0;
});
experienceSchema.virtual('projectCount').get(function () {
    return this.projects?.length || 0;
});
experienceSchema.virtual('isRecent').get(function () {
    const twoYearsAgo = new Date();
    twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
    return this.duration.startDate >= twoYearsAgo;
});
experienceSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.verificationScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
experienceSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});
experienceSchema.virtual('salaryRange').get(function () {
    if (!this.salary.amount) return null;
    const amount = this.salary.amount;
    if (amount < 50000) return 'entry';
    if (amount < 100000) return 'mid';
    if (amount < 200000) return 'senior';
    return 'executive';
});

// Middleware
experienceSchema.pre('save', async function (next) {
    try {
        // Auto-set isCurrent flag
        if (this.duration.endDate && this.duration.isCurrent) this.duration.isCurrent = false;
        else if (!this.duration.endDate && !this.duration.isCurrent) this.duration.isCurrent = true;

        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.jobTitle,
            this.description,
            this.department,
            ...this.skills.map(s => s.name),
            ...this.responsibilities.map(r => r.text),
            ...this.projects.map(p => p.name)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.isVerified) {
            let score = 30;
            const methodScores = { 'document': 25, 'hr-contact': 20, 'background-check': 30, 'linkedin-sync': 15, 'colleague': 15, 'email': 10, 'certificate': 20 };
            score += methodScores[this.verification.verificationMethod] || 0;
            if (this.verification.documents?.length > 0) score += 15;
            if (this.verification.hrContactVerified) score += 10;
            if (this.endorsements?.length > 0) score += Math.min(this.endorsements.length * 2, 20);
            if (this.media?.length > 0) score += 5;
            if (this.achievements?.length > 0) score += Math.min(this.achievements.length * 3, 15);
            this.verification.verificationScore = Math.min(score, 100);
        }

        // Calculate engagement and popularity scores
        let engagementScore = 0;
        engagementScore += (this.analytics.profileViews || 0) * 0.1;
        engagementScore += (this.analytics.likesCount || 0) * 2;
        engagementScore += (this.analytics.commentsCount || 0) * 3;
        engagementScore += (this.analytics.shareCount || 0) * 5;
        engagementScore += (this.endorsementCount || 0) * 4;
        engagementScore += (this.verification.verificationScore || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.verificationScore * 0.3) + (this.endorsementCount * 0.3);

        // Update cache metadata
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Cache in Redis
        await redisClient.setEx(`experience:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish score updates
        await redisClient.publish('experience_updates', JSON.stringify({
            experienceId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.recommendedSkills = this.skills?.map(skill => skill.name) || [];
        }

        // Update last active
        this.status.lastActiveAt = new Date();

        // Encrypt sensitive fields (placeholder)
        if (this.salary.amount) {
            this.salary.amount = await encryptField(this.salary.amount.toString());
        }

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

experienceSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        await redisClient.del(`experience:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

experienceSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.profileUpdates': 1 } }
        );

        // Update Company stats
        const Company = mongoose.model('Company');
        await Company.updateOne(
            { _id: doc.companyId },
            { $inc: { 'stats.employeeCount': doc.duration.isCurrent ? 1 : 0 }, $set: { 'analytics.lastCalculated': new Date() } }
        );

        // Sync to Algolia
        if (doc.privacy.searchable && doc.privacy.isPublic && doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user:experiences:${doc.userId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
experienceSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, shares: 0.2, endorsements: 0.2, verified: 0.1 };
    const viewScore = Math.log1p(this.analytics.profileViews) / Math.log1p(10000);
    const likeScore = Math.log1p(this.analytics.likesCount) / Math.log1p(1000);
    const commentScore = Math.log1p(this.analytics.commentsCount) / Math.log1p(500);
    const shareScore = Math.log1p(this.analytics.shareCount) / Math.log1p(500);
    const endorsementScore = Math.log1p(this.endorsementCount) / Math.log1p(100);
    const verifiedScore = this.verification.isVerified ? 1 : 0;
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        shareScore * weights.shares +
        endorsementScore * weights.endorsements +
        verifiedScore * weights.verified
    ) * 100);
};

// Static Methods
experienceSchema.statics.getUserExperiences = async function (userId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'startDate', sortOrder = -1, includeDeleted = false, filters = {}, includePrivate = false } = options;
    const cacheKey = `user:experiences:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true };
    if (!includeDeleted) baseQuery['status.isDeleted'] = false;
    if (!includePrivate) baseQuery['privacy.isPublic'] = true;
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') baseQuery[key] = value; });

    const results = await this.find(baseQuery)
        .sort({ [`duration.${sortBy}`]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({ path: 'companyId', select: 'name branding.logo industry size location stats.avgRating verification.isVerified' })
        .populate({ path: 'achievements', select: 'title type dateAchieved isPublic' })
        .populate({ path: 'endorsements.endorserId', select: 'name profilePic headline verification.isVerified' })
        .populate({ path: 'media', select: 'url type title' })
        .select('-connections.colleagues -metadata.importId')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

experienceSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', location = {}, skills = [], employmentType, workArrangement, seniorityLevel, salaryRange = {}, companySize, verified = false, hasProjects = false, hasAchievements = false, experience = {}, page = 1, limit = 20, sortBy = 'relevance', userId = null } = searchOptions;
    const cacheKey = `search:experiences:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                'status.workflow': 'published',
                ...(verified && { 'verification.isVerified': true }),
                ...(employmentType && { employmentType }),
                ...(workArrangement && { workArrangement }),
                ...(seniorityLevel && { seniorityLevel }),
                ...(location.country && { 'location.country': new RegExp(location.country, 'i') }),
                ...(location.city && { 'location.city': new RegExp(location.city, 'i') }),
                ...(location.isRemote !== undefined && { 'location.isRemote': location.isRemote }),
                ...(hasProjects && { 'projects.0': { $exists: true } }),
                ...(hasAchievements && { 'achievements.0': { $exists: true } })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        ...(skills.length > 0 ? [
            { $addFields: { skillMatchScore: { $divide: [{ $size: { $setIntersection: [skills, { $map: { input: '$skills', as: 'skill', in: '$$skill.name' } }] } }, skills.length] } } },
            { $match: { skillMatchScore: { $gt: 0 } } }
        ] : []),
        ...(experience.min || experience.max ? [
            { $addFields: { totalExperienceMonths: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44] } } },
            { $match: { ...(experience.min && { totalExperienceMonths: { $gte: experience.min * 12 } }), ...(experience.max && { totalExperienceMonths: { $lte: experience.max * 12 } }) } }
        ] : []),
        ...(salaryRange.min || salaryRange.max ? [{ $match: { 'salary.amount': { ...(salaryRange.min && { $gte: salaryRange.min }), ...(salaryRange.max && { $lte: salaryRange.max }) } } }] : []),
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company', pipeline: [{ $project: { name: 1, 'branding.logo': 1, 'industry.primary': 1, 'size.category': 1, 'stats.avgRating': 1, 'verification.isVerified': 1, 'locations.address': 1, contact: 1, description: 1 } }] } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        ...(companySize ? [{ $match: { 'company.size.category': companySize } }] : []),
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'userProfile', pipeline: [{ $project: { name: 1, profilePic: 1, headline: 1, location: 1, 'verification.isVerified': 1, premium: 1, connectionCount: { $size: { $ifNull: ['$connections', []] } }, followerCount: { $size: { $ifNull: ['$followers', []] } } } }] } },
        { $unwind: { path: '$userProfile', preserveNullAndEmptyArrays: true } },
        ...(userId ? [{ $addFields: { networkBoost: { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.connections'] }, 0.3, { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.followers'] }, 0.1, 0] }] } } }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $ifNull: ['$skillMatchScore', 0] }, 0.25] },
                        { $multiply: [{ $divide: ['$verification.verificationScore', 100] }, 0.15] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.1] },
                        { $multiply: [{ $ifNull: ['$company.stats.avgRating', 0] }, 0.05] },
                        { $multiply: [{ $cond: ['$userProfile.premium', 1, 0] }, 0.05] },
                        { $ifNull: ['$networkBoost', 0] },
                        { $multiply: [{ $divide: [{ $subtract: [new Date(), '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365 * 5] }, -0.05] },
                        { $multiply: [{ $add: [{ $cond: [{ $gt: [{ $size: { $ifNull: ['$achievements', []] } }, 0] }, 0.02, 0] }, { $cond: [{ $gt: [{ $size: { $ifNull: ['$projects', []] } }, 0] }, 0.02, 0] }, { $cond: [{ $gt: [{ $size: { $ifNull: ['$endorsements', []] } }, 0] }, 0.01, 0] }] }, 10] }
                    ]
                },
                popularityScore: this.calculatePopularityScore()
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                userId: 1,
                jobTitle: 1,
                department: 1,
                employmentType: 1,
                workArrangement: 1,
                seniorityLevel: 1,
                location: { $cond: ['$privacy.showLocation', '$location', { country: '$location.country', isRemote: '$location.isRemote' }] },
                duration: { $cond: ['$privacy.showDuration', '$duration', { isCurrent: '$duration.isCurrent' }] },
                description: { $cond: ['$privacy.showResponsibilities', { $substr: ['$description', 0, 200] }, null] },
                skills: { $slice: [{ $filter: { input: '$skills', cond: { $ne: ['$this.name', ''] } } }, 10] },
                achievements: { $cond: ['$privacy.showAchievements', { $size: { $ifNull: ['$achievements', []] } }, 0] },
                projects: { $cond: ['$privacy.showProjects', { $size: { $ifNull: ['$projects', []] } }, 0] },
                verification: { isVerified: '$verification.isVerified', level: '$verification.verificationScore' },
                salary: { $cond: ['$privacy.showSalary', '$salary', null] },
                company: 1,
                userProfile: { name: '$userProfile.name', profilePic: '$userProfile.profilePic', headline: '$userProfile.headline', verified: '$userProfile.verified', premium: '$userProfile.premium' },
                endorsementCount: { $size: { $ifNull: ['$endorsements', []] } },
                relevanceScore: 1,
                popularityScore: 1,
                createdAt: 1,
                updatedAt: 1,
                durationMonths: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44] }
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'experiences' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

experienceSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.verificationScore': -1 },
        'recent': { 'duration.startDate': -1, updatedAt: -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.profileViews': -1 },
        'salary-high': { 'salary.amount': -1 },
        'salary-low': { 'salary.amount': 1 },
        'experience': { durationMonths: -1 },
        'verified': { 'verification.verificationScore': -1, 'verification.isVerified': -1 },
        'alphabetical': { jobTitle: 1, 'company.name': 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

experienceSchema.statics.getTrendingInsights = async function (options = {}) {
    const { location, timeframe = 30, industry, limit = 25 } = options;
    const cacheKey = `trending:insights:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);
    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                createdAt: { $gte: startDate },
                ...(location && { 'location.country': location })
            }
        },
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company' } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        ...(industry ? [{ $match: { 'company.industry.primary': industry } }] : []),
        {
            $facet: {
                trendingTitles: [
                    { $group: { _id: { jobTitle: '$jobTitle', seniorityLevel: '$seniorityLevel' }, count: { $sum: 1 }, avgSalary: { $avg: '$salary.amount' }, uniqueCompanies: { $addToSet: '$companyId' }, totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } }, avgVerificationScore: { $avg: '$verification.verificationScore' } } },
                    { $addFields: { companyCount: { $size: '$uniqueCompanies' }, trendScore: { $multiply: ['$count', { $add: [{ $size: '$uniqueCompanies' }, 1] }, { $add: [{ $divide: ['$totalEndorsements', 10] }, 1] }] } } },
                    { $sort: { trendScore: -1 } },
                    { $limit: limit },
                    { $project: { jobTitle: '$_id.jobTitle', seniorityLevel: '$_id.seniorityLevel', occurrences: '$count', avgSalary: { $round: ['$avgSalary', 0] }, companyCount: 1, trendScore: 1, avgVerificationScore: { $round: ['$avgVerificationScore', 1] } } }
                ],
                trendingSkills: [
                    { $unwind: '$skills' },
                    { $group: { _id: '$skills.name', count: { $sum: 1 }, avgLevel: { $avg: { $switch: { branches: [{ case: { $eq: ['$skills.level', 'beginner'] }, then: 1 }, { case: { $eq: ['$skills.level', 'intermediate'] }, then: 2 }, { case: { $eq: ['$skills.level', 'advanced'] }, then: 3 }, { case: { $eq: ['$skills.level', 'expert'] }, then: 4 }], default: 2 } } }, endorsements: { $sum: { $cond: ['$skills.endorsed', 1, 0] } }, associatedSalaries: { $push: '$salary.amount' } } },
                    { $addFields: { avgSalary: { $avg: { $filter: { input: '$associatedSalaries', cond: { $gt: ['$this', 0] } } } }, endorsementRate: { $divide: ['$endorsements', '$count'] } } },
                    { $sort: { count: -1 } },
                    { $limit: limit },
                    { $project: { skill: '$_id', frequency: '$count', averageLevel: { $round: ['$avgLevel', 1] }, endorsementRate: { $round: ['$endorsementRate', 2] }, averageSalary: { $round: ['$avgSalary', 0] } } }
                ],
                employmentTrends: [
                    { $group: { _id: '$employmentType', count: { $sum: 1 }, avgSalary: { $avg: '$salary.amount' } } },
                    { $sort: { count: -1 } },
                    { $project: { type: '$_id', count: 1, avgSalary: { $round: ['$avgSalary', 0] }, percentage: { $multiply: [{ $divide: ['$count', { $sum: '$count' }] }, 100] } } }
                ],
                workArrangementTrends: [
                    { $group: { _id: '$workArrangement', count: { $sum: 1 } } },
                    { $sort: { count: -1 } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

experienceSchema.statics.getCareerAnalytics = async function (userId, options = {}) {
    const cacheKey = `career:analytics:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true, 'status.isDeleted': false } },
        { $sort: { 'duration.startDate': 1 } },
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company' } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        {
            $group: {
                _id: null,
                experiences: {
                    $push: {
                        jobTitle: '$jobTitle',
                        company: '$company.name',
                        industry: '$company.industry.primary',
                        companySize: '$company.size.category',
                        seniorityLevel: '$seniorityLevel',
                        startDate: '$duration.startDate',
                        endDate: '$duration.endDate',
                        isCurrent: '$duration.isCurrent',
                        durationMonths: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44] },
                        salary: '$salary.amount',
                        skills: '$skills',
                        achievements: { $size: { $ifNull: ['$achievements', []] } },
                        projects: { $size: { $ifNull: ['$projects', []] } },
                        endorsements: { $size: { $ifNull: ['$endorsements', []] } },
                        verificationScore: '$verification.verificationScore',
                        workArrangement: '$workArrangement'
                    }
                },
                totalExperienceMonths: { $sum: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44] } },
                avgTenureMonths: { $avg: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44] } },
                jobChanges: { $sum: 1 },
                uniqueCompanies: { $addToSet: '$companyId' },
                uniqueIndustries: { $addToSet: '$company.industry.primary' },
                allSkills: { $push: '$skills' },
                totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } },
                totalAchievements: { $sum: { $size: { $ifNull: ['$achievements', []] } } },
                totalProjects: { $sum: { $size: { $ifNull: ['$projects', []] } } },
                salaryProgression: { $push: { $cond: [{ $gt: ['$salary.amount', 0] }, { date: '$duration.startDate', amount: '$salary.amount', title: '$jobTitle' }, null] } },
                seniorityProgression: { $push: '$seniorityLevel' }
            }
        },
        {
            $addFields: {
                companyCount: { $size: '$uniqueCompanies' },
                industryCount: { $size: '$uniqueIndustries' },
                skillEvolution: { $reduce: { input: '$allSkills', initialValue: [], in: { $setUnion: ['$value', { $map: { input: '$this', as: 'skill', in: '$skill.name' } }] } } },
                cleanSalaryProgression: { $filter: { input: '$salaryProgression', cond: { $ne: ['$this', null] } } },
                avgTenureYears: { $divide: ['$avgTenureMonths', 12] },
                totalExperienceYears: { $divide: ['$totalExperienceMonths', 12] },
                careerVelocity: { $cond: [{ $gt: ['$totalExperienceMonths', 0] }, { $divide: ['$jobChanges', { $divide: ['$totalExperienceMonths', 12] }] }, 0] }
            }
        },
        {
            $project: {
                _id: 0,
                summary: { totalExperienceYears: { $round: ['$totalExperienceYears', 1] }, avgTenureYears: { $round: ['$avgTenureYears', 1] }, jobChanges: '$jobChanges', companyCount: '$companyCount', industryCount: '$industryCount', totalEndorsements: '$totalEndorsements', totalAchievements: '$totalAchievements', totalProjects: '$totalProjects', careerVelocity: { $round: ['$careerVelocity', 2] } },
                experiences: '$experiences',
                progression: { salary: '$cleanSalaryProgression', seniority: '$seniorityProgression' },
                skills: { total: { $size: '$skillEvolution' }, evolution: '$skillEvolution' },
                diversity: { companies: '$companyCount', industries: '$industryCount' }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

experienceSchema.statics.getMarketInsights = async function (options = {}) {
    const { jobTitle, location, seniorityLevel, skills = [], companySize, yearsExperience } = options;
    const cacheKey = `market:insights:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { 'status.isActive': true, 'status.isDeleted': false, 'privacy.isPublic': true, 'salary.amount': { $gt: 0 }, ...(jobTitle && { jobTitle: new RegExp(jobTitle, 'i') }), ...(location && { 'location.country': location }), ...(seniorityLevel && { seniorityLevel }) } },
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company' } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        ...(companySize ? [{ $match: { 'company.size.category': companySize } }] : []),
        { $addFields: { experienceYears: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365.25] } } },
        ...(yearsExperience ? [{ $match: { experienceYears: { $gte: yearsExperience.min || 0, $lte: yearsExperience.max || 50 } } }] : []),
        ...(skills.length > 0 ? [{ $match: { 'skills.name': { $in: skills } } }] : []),
        {
            $group: {
                _id: { jobTitle: '$jobTitle', seniorityLevel: '$seniorityLevel', country: '$location.country' },
                avgSalary: { $avg: '$salary.amount' },
                medianSalary: { $push: '$salary.amount' },
                minSalary: { $min: '$salary.amount' },
                maxSalary: { $max: '$salary.amount' },
                salaryCount: { $sum: 1 },
                avgExperience: { $avg: '$experienceYears' },
                totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } },
                companiesHiring: { $addToSet: '$companyId' },
                commonSkills: { $push: '$skills' },
                workArrangements: { $push: '$workArrangement' },
                samples: { $push: { company: '$company.name', salary: '$salary.amount', experience: '$experienceYears', verified: '$verification.isVerified' } }
            }
        },
        {
            $addFields: {
                medianSalary: { $let: { vars: { sortedSalaries: { $sortArray: { input: '$medianSalary', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedSalaries', { $floor: { $divide: [{ $size: '$sortedSalaries' }, 2] } }] } } },
                salaryP25: { $let: { vars: { sortedSalaries: { $sortArray: { input: '$medianSalary', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedSalaries', { $floor: { $multiply: [{ $size: '$sortedSalaries' }, 0.25] } }] } } },
                salaryP75: { $let: { vars: { sortedSalaries: { $sortArray: { input: '$medianSalary', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedSalaries', { $floor: { $multiply: [{ $size: '$sortedSalaries' }, 0.75] } }] } } },
                hiringCompanyCount: { $size: '$companiesHiring' },
                topSkills: { $slice: [{ $map: { input: { $setUnion: [{ $reduce: { input: '$commonSkills', initialValue: [], in: { $concatArrays: ['$value', '$this'] } } }] }, as: 'skill', in: '$skill.name' } }, 10] }
            }
        },
        { $sort: { salaryCount: -1 } },
        { $limit: 20 },
        { $project: { jobTitle: '$_id.jobTitle', seniorityLevel: '$_id.seniorityLevel', location: '$_id.country', salaryInsights: { average: { $round: ['$avgSalary', 0] }, median: { $round: ['$medianSalary', 0] }, min: '$minSalary', max: '$maxSalary', percentile25: { $round: ['$salaryP25', 0] }, percentile75: { $round: ['$salaryP75', 0] }, sampleSize: '$salaryCount' }, marketMetrics: { avgExperience: { $round: ['$avgExperience', 1] }, hiringCompanyCount: '$hiringCompanyCount', totalEndorsements: '$totalEndorsements' }, topSkills: '$topSkills', sampleData: { $slice: ['$samples', 5] } } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

experienceSchema.statics.bulkOperations = {
    updateVerification: async function (experienceIds, verificationData) {
        try {
            const bulkOps = experienceIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { 'verification.isVerified': verificationData.isVerified, 'verification.verificationDate': new Date(), 'verification.verifiedBy': verificationData.verifiedBy, 'verification.verificationMethod': verificationData.method, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of experienceIds) await redisClient.del(`experience:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk verification update error: ${error.message}`);
        }
    },
    updatePrivacy: async function (userId, privacySettings) {
        try {
            const result = await this.updateMany(
                { userId: new mongoose.Types.ObjectId(userId) },
                { $set: { privacy: { ...privacySettings, 'metadata.lastUpdated': new Date() } } }
            );
            await redisClient.del(`user:experiences:${userId}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk privacy update error: ${error.message}`);
        }
    },
    archiveOldExperiences: async function (cutoffDate) {
        try {
            const oldExperiences = await this.find({ 'duration.endDate': { $lt: cutoffDate }, 'status.isActive': true, 'status.isDeleted': false }).lean();
            if (oldExperiences.length === 0) return { archived: 0 };
            const ArchiveExperience = mongoose.model('ArchiveExperience', experienceSchema, 'archive_experiences');
            await ArchiveExperience.insertMany(oldExperiences);
            const result = await this.updateMany(
                { _id: { $in: oldExperiences.map(e => e._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date(), 'metadata.lastUpdated': new Date() } }
            );
            for (const exp of oldExperiences) await redisClient.del(`experience:${exp._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive old experiences error: ${error.message}`);
        }
    },
    updateSkills: async function (experienceIds, skillUpdates) {
        try {
            const bulkOps = experienceIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $set: { skills: skillUpdates, 'metadata.lastUpdated': new Date(), 'metadata.updateCount': { $inc: 1 } } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of experienceIds) await redisClient.del(`experience:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk skills update error: ${error.message}`);
        }
    },
    addEndorsement: async function (experienceIds, endorsementData) {
        try {
            const bulkOps = experienceIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $push: { endorsements: endorsementData }, $inc: { 'analytics.endorsementCount': 1 } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of experienceIds) await redisClient.del(`experience:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk endorsement add error: ${error.message}`);
        }
    }
};

experienceSchema.statics.getAIRecommendations = async function (userId, options = {}) {
    const { type = 'career-growth', limit = 10 } = options;
    const cacheKey = `ai:recommendations:${userId}:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true } },
        { $group: { _id: null, currentSkills: { $push: { $map: { input: '$skills', as: 'skill', in: '$skill.name' } } }, industries: { $addToSet: '$company.industry.primary' }, currentLevel: { $last: '$seniorityLevel' }, currentSalary: { $last: '$salary.amount' }, totalExperience: { $sum: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365.25] } } } },
        { $lookup: { from: 'experiences', pipeline: [{ $match: { 'status.isActive': true, 'privacy.isPublic': true, userId: { $ne: new mongoose.Types.ObjectId(userId) } } }, { $sample: { size: 1000 } }], as: 'marketData' } },
        {
            $project: {
                recommendations: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'career-growth'] }, then: { nextRoles: { $cond: [{ $eq: ['$currentLevel', 'entry-level'] }, ['associate', 'mid-senior'], { $eq: ['$currentLevel', 'mid-senior'] }, ['senior', 'director'], ['executive', 'c-level']] }, skillsToLearn: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.skills', initialValue: [], in: { $setUnion: ['$value', '$this.name'] } } }, '$currentSkills'] }, limit] }, targetSalaryRange: { min: { $multiply: ['$currentSalary', 1.15] }, max: { $multiply: ['$currentSalary', 1.4] } } } },
                            { case: { $eq: [type, 'skill-development'] }, then: { trendingSkills: { $slice: [{ $reduce: { input: '$marketData.skills', initialValue: [], in: { $setUnion: ['$value', '$this.name'] } } }, limit] }, skillGaps: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.skills', initialValue: [], in: { $setUnion: ['$value', '$this.name'] } } }, '$currentSkills'] }, limit] } } },
                            { case: { $eq: [type, 'networking'] }, then: { recommendedConnections: { $slice: [{ $reduce: { input: '$marketData.userId', initialValue: [], in: { $setUnion: ['$value', '$this'] } } }, limit] } } }
                        ],
                        default: { message: 'Invalid recommendation type' }
                    }
                }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

experienceSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:metrics:${timeframe}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    const days = parseInt(timeframe.replace('d', ''));
    startDate.setDate(startDate.getDate() - days);
    const pipeline = [
        {
            $facet: {
                queryStats: [{ $match: { 'metadata.lastUpdated': { $gte: startDate } } }, { $group: { _id: null, totalQueries: { $sum: 1 }, avgResponseTime: { $avg: '$analytics.responseTime' }, errorRate: { $avg: { $cond: ['$analytics.hasError', 1, 0] } } } }],
                indexStats: [{ $group: { _id: '$metadata.source', count: { $sum: 1 }, avgVerificationScore: { $avg: '$verification.verificationScore' } } }],
                dataQuality: [
                    {
                        $group: {
                            _id: null,
                            totalRecords: { $sum: 1 },
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$jobTitle', ''] }, { $ne: ['$description', ''] }, { $gt: [{ $size: { $ifNull: ['$skills', []] } }, 0] }] }, 1, 0] } },
                            verifiedRecords: { $sum: { $cond: ['$verification.isVerified', 1, 0] } },
                            withSalaryInfo: { $sum: { $cond: [{ $gt: ['$salary.amount', 0] }, 1, 0] } },
                            withEndorsements: { $sum: { $cond: [{ $gt: [{ $size: { $ifNull: ['$endorsements', []] } }, 0] }, 1, 0] } }
                        }
                    },
                    { $addFields: { completenessRate: { $multiply: [{ $divide: ['$completeProfiles', '$totalRecords'] }, 100] }, verificationRate: { $multiply: [{ $divide: ['$verifiedRecords', '$totalRecords'] }, 100] }, salaryTransparency: { $multiply: [{ $divide: ['$withSalaryInfo', '$totalRecords'] }, 100] }, endorsementRate: { $multiply: [{ $divide: ['$withEndorsements', '$totalRecords'] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

experienceSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'experience_text_search', 'userId_1_duration.startDate_-1_status.isActive_1', 'companyId_1_jobTitle_1_status.isActive_1'];
    const unusedIndexes = indexes.filter(idx => !essentialIndexes.includes(idx.name) && !idx.name.includes('2dsphere'));
    let dropped = 0;
    for (const idx of unusedIndexes) {
        try {
            await this.collection.dropIndex(idx.name);
            dropped++;
        } catch (err) {
            console.error(`Failed to drop index ${idx.name}:`, err);
        }
    }
    return { dropped };
};

experienceSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const experienceId = change.documentKey._id.toString();
        await redisClient.del(`experience:${experienceId}`);
        await redisClient.publish('experience_updates', JSON.stringify({
            experienceId,
            operation: change.operationType,
            updatedFields: change.updateDescription?.updatedFields
        }));
    });
    return changeStream;
};

// Placeholder for CSFLE
async function encryptField(value) {
    // Requires MongoDB CSFLE setup
    // Example:
    /*
    import { ClientEncryption } from 'mongodb';
    const encryption = new ClientEncryption(mongoose.connection.client, {
      keyVaultNamespace: 'encryption.__keyVault',
      kmsProviders: { local: { key: process.env.ENCRYPTION_KEY } }
    });
    return await encryption.encrypt(value, {
      algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
      keyId: process.env.ENCRYPTION_KEY_ID
    });
    */
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugins
experienceSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    experienceSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'experiences',
        selector: 'jobTitle description skills.name location.city location.country companyId cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: { jobTitle: v => v || '', description: v => v || '', 'skills.name': v => v || [], 'location.city': v => v || '', 'location.country': v => v || '', 'cache.searchVector': v => v || '' },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    experienceSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    experienceSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
}

export default mongoose.model('Experience', experienceSchema);

ye mere linkdin ke application ke profile ke liye hai jo mere scalable projects ke liye hai jisme ki ham isko production level me lekar bana rahe hai to aap isko linkdin ke profile service ke acording skill service ke liye updated skill model generate karke do
please generate it and it will for 1 millions users and it will scale and advanced level like thousands of lines and its more and enhanced  