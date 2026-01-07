import html from "eslint-plugin-html";
import globals from "globals";

// Shared functions and variables from shared.js that are available globally
const sharedGlobals = {
    // Functions
    initSharedPage: "readonly",
    toggleFilterVisible: "readonly",
    getSelectedValues: "readonly",
    buildQueryParams: "readonly",
    loadFilterOptions: "readonly",
    initializeMultiselects: "readonly",
    applyUrlFilters: "readonly",
    addCellToRow: "readonly",
    formatNumber: "readonly",
    formatRiskNumber: "readonly",
    formatTimestamp: "readonly",
    escapeHtml: "readonly",
    isScanComplete: "readonly",
    loadDataTable: "readonly",
    onFilterChange: "readonly",
    goToPage: "readonly",
    nextPage: "readonly",
    prevPage: "readonly",
    renderPagination: "readonly",
    updateCSVLink: "readonly",
    sortByColumn: "readonly",
    updateSortIndicators: "readonly",
    loadConfig: "readonly",
    getCurrentFilterQueryString: "readonly",
    renderSidebarNav: "readonly",
    renderVersionFooter: "readonly",
    checkForUpdates: "readonly",
    initPage: "readonly",
    // Global variables
    pageConfig: "writable",
    currentPage: "writable",
    pageSize: "writable",
    totalPages: "writable",
    totalItems: "writable",
    sortBy: "writable",
    sortOrder: "writable",
    filtersVisible: "writable",
    multiselectInstances: "writable",
    appConfig: "writable",
    currentTimestamp: "writable",
};

export default [
    {
        // Match any HTML file passed on the command line
        files: ["**/*.html"],
        plugins: {
            html,
        },
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "script",
            globals: {
                ...globals.browser,
                ...sharedGlobals,
            },
        },
        rules: {
            "indent": "off",
            "linebreak-style": ["error", "unix"],
            "quotes": "off",
            "semi": ["warn", "always"],
            "no-unused-vars": "off",
            "no-console": "off",
            "no-undef": "warn",
            "no-redeclare": "off",
        },
    },
];
