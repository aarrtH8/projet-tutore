'use client'

import { useState, useMemo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { SeverityBadge } from '@/components/severity-badge'
import { Vulnerability } from '@/lib/mock-data'
import { Download, Search, ArrowUpDown } from 'lucide-react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface VulnerabilitiesTableProps {
  vulnerabilities: Vulnerability[]
}

export function VulnerabilitiesTable({ vulnerabilities }: VulnerabilitiesTableProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [sortField, setSortField] = useState<keyof Vulnerability>('cvssScore')
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc')
  const [itemsPerPage, setItemsPerPage] = useState(10)
  const [currentPage, setCurrentPage] = useState(1)

  // Get unique categories
  const categories = useMemo(
    () => Array.from(new Set(vulnerabilities.map((v) => v.category))),
    [vulnerabilities]
  )

  // Filter and sort vulnerabilities
  const filteredVulnerabilities = useMemo(() => {
    let filtered = vulnerabilities.filter((vuln) => {
      const matchesSearch =
        vuln.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        vuln.cve.toLowerCase().includes(searchTerm.toLowerCase()) ||
        vuln.affectedSystem.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter
      const matchesCategory = categoryFilter === 'all' || vuln.category === categoryFilter
      return matchesSearch && matchesSeverity && matchesCategory
    })

    // Sort
    filtered.sort((a, b) => {
      const aValue = a[sortField]
      const bValue = b[sortField]
      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1
      return 0
    })

    return filtered
  }, [vulnerabilities, searchTerm, severityFilter, categoryFilter, sortField, sortDirection])

  // Pagination
  const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage)
  const paginatedVulnerabilities = filteredVulnerabilities.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  const handleSort = (field: keyof Vulnerability) => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
  }

  const exportData = (format: 'json' | 'csv' | 'xml') => {
    const data = filteredVulnerabilities

    if (format === 'json') {
      const json = JSON.stringify(data, null, 2)
      downloadFile(json, 'vulnerabilities.json', 'application/json')
    } else if (format === 'csv') {
      const headers = ['Sévérité', 'Catégorie', 'CVE', 'Système Affecté', 'Score CVSS', 'Description', 'Remédiation']
      const rows = data.map((v) => [
        v.severity,
        v.category,
        v.cve,
        v.affectedSystem,
        v.cvssScore,
        v.description,
        v.remediation,
      ])
      const csv = [headers, ...rows].map((row) => row.map((cell) => `"${cell}"`).join(',')).join('\n')
      downloadFile(csv, 'vulnerabilities.csv', 'text/csv')
    } else if (format === 'xml') {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<panoptis_audit>
  <vulnerabilities>
${data
  .map(
    (v) => `    <vulnerability>
      <severity>${v.severity}</severity>
      <category>${v.category}</category>
      <cve>${v.cve}</cve>
      <affected_system>${v.affectedSystem}</affected_system>
      <cvss_score>${v.cvssScore}</cvss_score>
      <description>${v.description}</description>
      <remediation>${v.remediation}</remediation>
    </vulnerability>`
  )
  .join('\n')}
  </vulnerabilities>
</panoptis_audit>`
      downloadFile(xml, 'vulnerabilities.xml', 'application/xml')
    }
  }

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <CardTitle>Liste des Vulnérabilités</CardTitle>
            <CardDescription>
              {filteredVulnerabilities.length} vulnérabilité(s) trouvée(s)
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => exportData('json')}>
              <Download className="h-4 w-4 mr-2" />
              JSON
            </Button>
            <Button variant="outline" size="sm" onClick={() => exportData('csv')}>
              <Download className="h-4 w-4 mr-2" />
              CSV
            </Button>
            <Button variant="outline" size="sm" onClick={() => exportData('xml')}>
              <Download className="h-4 w-4 mr-2" />
              XML
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {/* Filters */}
        <div className="grid gap-4 md:grid-cols-3 mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Rechercher..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value)
                setCurrentPage(1)
              }}
              className="pl-9"
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filtrer par sévérité" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Toutes les sévérités</SelectItem>
              <SelectItem value="Critique">Critique</SelectItem>
              <SelectItem value="Haute">Haute</SelectItem>
              <SelectItem value="Moyenne">Moyenne</SelectItem>
              <SelectItem value="Basse">Basse</SelectItem>
            </SelectContent>
          </Select>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filtrer par catégorie" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Toutes les catégories</SelectItem>
              {categories.map((cat) => (
                <SelectItem key={cat} value={cat}>
                  {cat}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Table */}
        <div className="rounded-md border overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleSort('severity')}
                    className="h-8 px-2"
                  >
                    Sévérité
                    <ArrowUpDown className="ml-2 h-3 w-3" />
                  </Button>
                </TableHead>
                <TableHead>Catégorie</TableHead>
                <TableHead>CVE</TableHead>
                <TableHead>Système Affecté</TableHead>
                <TableHead>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleSort('cvssScore')}
                    className="h-8 px-2"
                  >
                    CVSS
                    <ArrowUpDown className="ml-2 h-3 w-3" />
                  </Button>
                </TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Remédiation</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedVulnerabilities.map((vuln) => (
                <TableRow key={vuln.id}>
                  <TableCell>
                    <SeverityBadge severity={vuln.severity} />
                  </TableCell>
                  <TableCell className="font-medium">{vuln.category}</TableCell>
                  <TableCell>
                    <code className="font-mono text-sm bg-muted px-2 py-1 rounded">
                      {vuln.cve}
                    </code>
                  </TableCell>
                  <TableCell className="text-sm">{vuln.affectedSystem}</TableCell>
                  <TableCell>
                    <span className="font-semibold">{vuln.cvssScore}</span>
                  </TableCell>
                  <TableCell className="max-w-xs">
                    <p className="text-sm line-clamp-2">{vuln.description}</p>
                  </TableCell>
                  <TableCell className="max-w-xs">
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {vuln.remediation}
                    </p>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Afficher</span>
            <Select
              value={itemsPerPage.toString()}
              onValueChange={(value) => {
                setItemsPerPage(Number(value))
                setCurrentPage(1)
              }}
            >
              <SelectTrigger className="w-20">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">10</SelectItem>
                <SelectItem value="25">25</SelectItem>
                <SelectItem value="50">50</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground">par page</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
            >
              Précédent
            </Button>
            <span className="text-sm">
              Page {currentPage} sur {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
            >
              Suivant
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
