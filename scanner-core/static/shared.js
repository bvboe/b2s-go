// Shared JavaScript functionality for bjorn2scan UI
// This file contains common code used by images.html, pods.html, etc.

// Global page configuration - must be set by each page before calling init
let pageConfig = {
    apiEndpoint: null,      // e.g., '/api/images' or '/api/pods'
    dataKey: null,          // e.g., 'images' or 'pods'
    pageTitle: null,        // e.g., 'Image Summary' or 'Pods'
    currentPageUrl: null,   // e.g., 'images.html' or 'pods.html'
    defaultSortBy: null,    // e.g., 'image' or 'namespace'
    columnCount: null,      // Total number of columns in the table
    renderRow: null         // Function to render a table row
};

// State management
let currentPage = 1;
let pageSize = 50;
let totalPages = 1;
let totalItems = 0;
let sortBy = null;
let sortOrder = 'ASC';
let filtersVisible = true;
let multiselectInstances = {}; // Store custom multiselect instances

// Initialize page with configuration
function initSharedPage(config) {
    pageConfig = config;
    sortBy = config.defaultSortBy;
}

// Filter visibility toggle
function toggleFilterVisible() {
    const filterDetails = document.getElementById('filterDetails');
    const filterCell = document.getElementById('filterCell');
    const filterContainer = document.getElementById('filterContainer');

    if (filtersVisible) {
        filterDetails.style.display = 'none';
        filterCell.className = 'filterUnSelected';
        filterContainer.className = 'filterContainerUnSelected';
    } else {
        filterDetails.style.display = '';
        filterCell.className = 'filterSelected';
        filterContainer.className = 'filterContainerSelected';
    }
    filtersVisible = !filtersVisible;
}

// Get selected values from multi-select
function getSelectedValues(selectId) {
    const instance = multiselectInstances[selectId];
    return instance ? instance.getSelected() : [];
}

// Custom MultiSelect class
class CustomMultiSelect {
    static instances = []; // Track all instances

    constructor(selectElement, placeholder = 'Select options') {
        this.selectElement = selectElement;
        this.selectElement.style.display = 'none';
        this.placeholder = placeholder;
        this.selected = [];
        this.options = Array.from(selectElement.options).map(opt => ({
            value: opt.value,
            text: opt.text
        }));

        this.createUI();
        this.attachEvents();
        CustomMultiSelect.instances.push(this);
    }

    createUI() {
        this.container = document.createElement('div');
        this.container.className = 'custom-multiselect';

        this.header = document.createElement('div');
        this.header.className = 'multiselect-header';

        this.placeholderElement = document.createElement('span');
        this.placeholderElement.className = 'multiselect-placeholder';
        this.placeholderElement.textContent = this.placeholder;
        this.header.appendChild(this.placeholderElement);

        this.arrow = document.createElement('div');
        this.arrow.className = 'multiselect-arrow';
        this.header.appendChild(this.arrow);

        this.dropdown = document.createElement('div');
        this.dropdown.className = 'multiselect-dropdown';

        this.options.forEach(opt => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'multiselect-option';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = opt.value;
            checkbox.dataset.text = opt.text;

            const label = document.createElement('span');
            label.textContent = opt.text;

            optionDiv.appendChild(checkbox);
            optionDiv.appendChild(label);
            this.dropdown.appendChild(optionDiv);
        });

        this.container.appendChild(this.header);
        this.container.appendChild(this.dropdown);
        this.selectElement.parentNode.insertBefore(this.container, this.selectElement);
    }

    attachEvents() {
        this.header.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggle();
        });

        this.dropdown.addEventListener('click', (e) => {
            e.stopPropagation();
            if (e.target.type === 'checkbox') {
                this.handleSelection(e.target);
            } else if (e.target.closest('.multiselect-option')) {
                const checkbox = e.target.closest('.multiselect-option').querySelector('input');
                checkbox.checked = !checkbox.checked;
                this.handleSelection(checkbox);
            }
        });

        document.addEventListener('click', () => {
            this.close();
        });
    }

    toggle() {
        const isOpening = !this.dropdown.classList.contains('open');
        if (isOpening) {
            CustomMultiSelect.instances.forEach(instance => {
                if (instance !== this) {
                    instance.close();
                }
            });
        }
        this.dropdown.classList.toggle('open');
    }

    close() {
        this.dropdown.classList.remove('open');
    }

    handleSelection(checkbox) {
        const value = checkbox.value;
        const text = checkbox.dataset.text;

        if (checkbox.checked) {
            if (!this.selected.find(s => s.value === value)) {
                this.selected.push({ value, text });
            }
        } else {
            this.selected = this.selected.filter(s => s.value !== value);
        }

        this.updateHeader();
        onFilterChange();
    }

    updateHeader() {
        this.header.innerHTML = '';

        if (this.selected.length === 0) {
            this.placeholderElement = document.createElement('span');
            this.placeholderElement.className = 'multiselect-placeholder';
            this.placeholderElement.textContent = this.placeholder;
            this.header.appendChild(this.placeholderElement);
        } else {
            this.selected.forEach(item => {
                const tag = document.createElement('span');
                tag.className = 'multiselect-tag';
                tag.innerHTML = `${item.text} <span class="multiselect-tag-remove">×</span>`;
                tag.querySelector('.multiselect-tag-remove').addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.removeItem(item.value);
                });
                this.header.appendChild(tag);
            });
        }

        this.arrow = document.createElement('div');
        this.arrow.className = 'multiselect-arrow';
        this.header.appendChild(this.arrow);
    }

    removeItem(value) {
        this.selected = this.selected.filter(s => s.value !== value);
        const checkbox = this.dropdown.querySelector(`input[value="${value}"]`);
        if (checkbox) checkbox.checked = false;
        this.updateHeader();
        onFilterChange();
    }

    getSelected() {
        return this.selected.map(s => s.value);
    }
}

// Build URL with current filters and sort
function buildQueryParams(includeFormat = false) {
    const params = new URLSearchParams();
    params.append('page', currentPage);
    params.append('pageSize', includeFormat ? 10000 : pageSize);
    params.append('sortBy', sortBy);
    params.append('sortOrder', sortOrder);

    const namespaces = getSelectedValues('namespaceFilter');
    if (namespaces.length) params.append('namespaces', namespaces.join(','));

    const vulnStatuses = getSelectedValues('vulnerabilityStatusFilter');
    if (vulnStatuses.length) params.append('vulnStatuses', vulnStatuses.join(','));

    const packageTypes = getSelectedValues('packageTypeFilter');
    if (packageTypes.length) params.append('packageTypes', packageTypes.join(','));

    const osNames = getSelectedValues('osNameFilter');
    if (osNames.length) params.append('osNames', osNames.join(','));

    if (includeFormat) {
        params.append('format', 'csv');
    }

    return params;
}

// Load filter options
async function loadFilterOptions() {
    try {
        const response = await fetch('/api/filter-options');
        if (!response.ok) throw new Error('Failed to load filter options');

        const data = await response.json();

        const nsSelect = document.getElementById('namespaceFilter');
        nsSelect.innerHTML = (data.namespaces || []).map(ns =>
            `<option value="${escapeHtml(ns)}">${escapeHtml(ns)}</option>`
        ).join('');

        const vulnSelect = document.getElementById('vulnerabilityStatusFilter');
        vulnSelect.innerHTML = (data.vulnStatuses || []).map(status =>
            `<option value="${escapeHtml(status)}">${escapeHtml(status)}</option>`
        ).join('');

        const pkgSelect = document.getElementById('packageTypeFilter');
        pkgSelect.innerHTML = (data.packageTypes || []).map(type =>
            `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`
        ).join('');

        const osSelect = document.getElementById('osNameFilter');
        osSelect.innerHTML = (data.osNames || []).map(os =>
            `<option value="${escapeHtml(os)}">${escapeHtml(os)}</option>`
        ).join('');

        initializeMultiselects();

    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Initialize custom multi-select dropdowns
function initializeMultiselects() {
    const filters = [
        { id: 'namespaceFilter', placeholder: 'All namespaces' },
        { id: 'vulnerabilityStatusFilter', placeholder: 'All statuses' },
        { id: 'packageTypeFilter', placeholder: 'All package types' },
        { id: 'osNameFilter', placeholder: 'All distributions' }
    ];

    filters.forEach(filter => {
        const element = document.getElementById(filter.id);
        if (element && !multiselectInstances[filter.id]) {
            multiselectInstances[filter.id] = new CustomMultiSelect(element, filter.placeholder);
        }
    });
}

// Add cell to row
function addCellToRow(row, align, text) {
    const cell = document.createElement('td');
    cell.style.textAlign = align;
    cell.textContent = text;
    row.appendChild(cell);
    return cell;
}

// Format number with commas
function formatNumber(num) {
    if (num === null || num === undefined || num === 0) return '0';
    return num.toLocaleString();
}

// Format risk number
function formatRiskNumber(risk) {
    if (risk === null || risk === undefined || risk === 0) {
        return '0.0';
    }
    if (risk < 0.1) {
        return '< 0.1';
    }
    return risk.toFixed(1);
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

// Check if scan is complete based on status description
function isScanComplete(statusDescription) {
    return statusDescription === 'Scan complete';
}

// Load data table
async function loadDataTable() {
    const tableBody = document.querySelector('#vulnerabilityTable tbody');

    try {
        const params = buildQueryParams(false);
        const response = await fetch(`${pageConfig.apiEndpoint}?${params}`);

        if (!response.ok) {
            throw new Error(`Failed to load data: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        tableBody.innerHTML = '';

        totalPages = data.totalPages || 1;
        totalItems = data.totalCount || 0;
        currentPage = data.page || currentPage;

        (data[pageConfig.dataKey] || []).forEach(item => {
            const row = document.createElement('tr');
            row.classList.add('clickable-row');

            // Call page-specific row rendering
            pageConfig.renderRow(row, item);

            tableBody.appendChild(row);
        });

        renderPagination();

    } catch (error) {
        console.error('Error loading data:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', '⚠️ Error loading data: ' + error.message);
        cell.colSpan = pageConfig.columnCount;
        cell.style.color = 'red';
        tableBody.appendChild(row);
        renderPagination();
    }
}

// Handle filter changes
function onFilterChange() {
    currentPage = 1;
    loadDataTable();
    updateCSVLink();
}

// Pagination functions
function goToPage(page) {
    if (page < 1 || page > totalPages) return;
    currentPage = page;
    loadDataTable();
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        loadDataTable();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadDataTable();
    }
}

function renderPagination() {
    const paginationDiv = document.getElementById('pagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = '';
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';

    html += `<button onclick="prevPage()" ${currentPage === 1 ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === 1 ? 'default' : 'pointer'};">Previous</button>`;

    html += '<div style="display: flex; gap: 5px;">';

    if (currentPage > 3) {
        html += `<button onclick="goToPage(1)" style="padding: 5px 10px; cursor: pointer;">1</button>`;
        if (currentPage > 4) {
            html += `<span style="padding: 5px;">...</span>`;
        }
    }

    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        if (i === currentPage) {
            html += `<button style="padding: 5px 10px; font-weight: bold; background: lightgrey;">${i}</button>`;
        } else {
            html += `<button onclick="goToPage(${i})" style="padding: 5px 10px; cursor: pointer;">${i}</button>`;
        }
    }

    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) {
            html += `<span style="padding: 5px;">...</span>`;
        }
        html += `<button onclick="goToPage(${totalPages})" style="padding: 5px 10px; cursor: pointer;">${totalPages}</button>`;
    }

    html += '</div>';

    html += `<button onclick="nextPage()" ${currentPage === totalPages ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === totalPages ? 'default' : 'pointer'};">Next</button>`;

    const startItem = (currentPage - 1) * pageSize + 1;
    const endItem = Math.min(currentPage * pageSize, totalItems);
    html += `<span style="margin-left: 20px; color: #666;">Showing ${startItem}-${endItem} of ${totalItems}</span>`;

    html += '</div>';

    paginationDiv.innerHTML = html;
}

// Update CSV export link
function updateCSVLink() {
    const params = buildQueryParams(true);
    document.getElementById('csvlink').href = `${pageConfig.apiEndpoint}?${params}`;
}

// Sort by column
function sortByColumn(column) {
    if (sortBy === column) {
        sortOrder = sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        sortBy = column;
        sortOrder = 'ASC';
    }
    updateSortIndicators();
    loadDataTable();
}

// Update sort indicators on column headers
function updateSortIndicators() {
    document.querySelectorAll('th.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sortField === sortBy) {
            th.classList.add(sortOrder === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// Global config storage
let appConfig = {
    clusterName: 'bjorn2scan',
    version: '1.0.0',
    scanContainers: true,
    scanNodes: false
};

// Load configuration from API
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error('Failed to load config');
        }
        const data = await response.json();

        appConfig.clusterName = data.clusterName || appConfig.clusterName;
        appConfig.version = data.version || appConfig.version;
        appConfig.scanContainers = data.scanContainers !== undefined ? data.scanContainers : appConfig.scanContainers;
        appConfig.scanNodes = data.scanNodes !== undefined ? data.scanNodes : appConfig.scanNodes;

        const clusterNameDiv = document.getElementById('clusterName');
        clusterNameDiv.textContent = pageConfig.pageTitle + ' - ' + appConfig.clusterName;

        document.title = pageConfig.pageTitle + ' - ' + appConfig.clusterName;

    } catch (error) {
        console.error('Error loading config:', error);
    }
}

// Render sidebar navigation
function renderSidebarNav() {
    const tableBody = document.getElementById('sidebarNav');
    if (!tableBody) return;

    tableBody.innerHTML = '';

    const showContainerScans = appConfig.scanContainers;
    const showNodeScans = appConfig.scanNodes;

    function addNavItem(title, url) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');

        const isCurrentPage = url === pageConfig.currentPageUrl;
        const decoration = isCurrentPage ? '<u>' : '';
        const decorationEnd = isCurrentPage ? '</u>' : '';

        cell.innerHTML = `<h2><a href="${url}">${decoration}${title}${decorationEnd}</a></h2>`;
        row.appendChild(cell);
        tableBody.appendChild(row);
    }

    addNavItem('Summary', 'index.html');
    if (showContainerScans) {
        addNavItem('Images', 'images.html');
        addNavItem('Pods', 'pods.html');
    }
    if (showNodeScans) {
        addNavItem('Nodes', 'nodes.html');
    }
    if (showContainerScans) {
        addNavItem('CVEs', 'cves.html');
        addNavItem('SBOM', 'sbom.html');
    }
}

// Render version footer
function renderVersionFooter() {
    const footer = document.getElementById('app-footer');
    if (!footer) return;

    footer.innerHTML = `<p style="text-align: right; color: #666; font-style: italic;"><a href="https://github.com/bvboe/b2s-go" target="_blank" style="color: #666; text-decoration: underline;">bjorn2scan v${appConfig.version}</a></p>`;
}

// Auto-refresh functionality
let currentTimestamp = null;

async function checkForUpdates() {
    try {
        const response = await fetch("/api/lastupdated?datatype=image");
        if (!response.ok) {
            console.error("Failed to fetch last updated timestamp");
            return;
        }

        const newTimestamp = await response.text();

        if (currentTimestamp === null) {
            // First time - just store the timestamp
            currentTimestamp = newTimestamp;
        } else if (newTimestamp !== currentTimestamp) {
            // Timestamp changed - reload data
            console.log("Data updated, reloading...");
            currentTimestamp = newTimestamp;
            loadDataTable();
        }
    } catch (error) {
        console.error("Error checking for updates:", error);
    }
}

// Initialize page
async function initPage() {
    await loadConfig();
    renderSidebarNav();
    renderVersionFooter();
    await loadFilterOptions();
    loadDataTable();
    updateCSVLink();
    updateSortIndicators();

    // Start polling for updates every 2 seconds
    setInterval(checkForUpdates, 2000);
}
