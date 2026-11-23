import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { authenticatedRoutes } from './routes'

test.skip(
  !process.env.EASYPI_E2E_USERNAME || !process.env.EASYPI_E2E_PASSWORD,
  'test administrator credentials were not supplied',
)

interface PageControls {
  route: string
  headings: string[]
  buttons: string[]
  fields: Array<{ type: string; name: string }>
}

const outputPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../.build/acceptance/ui-control-inventory.json',
)

test('catalogue visible controls without changing server state', async ({ page }) => {
  const inventory: PageControls[] = []
  page.setDefaultNavigationTimeout(15_000)

  for (const route of authenticatedRoutes) {
    await test.step(route, async () => {
      await page.goto(route, { waitUntil: 'domcontentloaded', timeout: 15_000 })
      await expect(page).not.toHaveURL(/\/login(?:[/?#]|$)/)
      await expect(page.locator('main').first()).toBeVisible()
      await page.waitForTimeout(350)

      const headings = await page.locator('main h1:visible, main h2:visible').allTextContents()
      const buttons = await page.locator('main button:visible').evaluateAll((elements) =>
        elements.map((element) => {
          const aria = element.getAttribute('aria-label') || element.getAttribute('title')
          return (aria || element.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160)
        }).filter(Boolean),
      )
      const fields = await page.locator('main input:visible, main textarea:visible, main select:visible')
        .evaluateAll((elements) => elements.map((element) => ({
          type: element.tagName.toLowerCase() === 'input'
            ? element.getAttribute('type') || 'text'
            : element.tagName.toLowerCase(),
          name: (
            element.getAttribute('aria-label')
            || element.getAttribute('placeholder')
            || element.getAttribute('name')
            || element.getAttribute('id')
            || '<unlabelled>'
          ).replace(/\s+/g, ' ').trim().slice(0, 160),
        })))
      inventory.push({
        route,
        headings: [...new Set(headings.map((value) => value.replace(/\s+/g, ' ').trim()))],
        buttons: [...new Set(buttons)],
        fields,
      })
    })
  }

  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(outputPath, `${JSON.stringify(inventory, null, 2)}\n`, 'utf8')
})
